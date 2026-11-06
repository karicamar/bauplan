using System.Text.Json;
using System.Text.Json.Nodes;

namespace Bauplan.Core.Plan;

/// <summary>What Terraform will do with one resource (from <c>resource_changes[].change.actions</c>).</summary>
public enum ChangeAction
{
    NoOp,
    Create,
    Read,
    Update,
    Delete,

    /// <summary>delete + create (in either order): the resource is destroyed and a new one is built.</summary>
    Replace,
}

/// <summary>One entry of <c>resource_changes</c>: the resource before and after the plan.</summary>
public sealed record ResourceChange
{
    public required string Address { get; init; }
    public required string Type { get; init; }
    public required string Name { get; init; }
    public string? ModuleAddress { get; init; }
    public string ProviderName { get; init; } = "";
    public required ChangeAction Action { get; init; }

    /// <summary>For a replace: true when the new resource is created before the old one is destroyed.</summary>
    public bool CreateBeforeDestroy { get; init; }

    public JsonObject? Before { get; init; }
    public JsonObject? After { get; init; }

    /// <summary>Same shape as <see cref="After"/>, with <c>true</c> where the value is only known after apply.</summary>
    public JsonObject? AfterUnknown { get; init; }

    /// <summary>The attributes that force a replacement (Terraform 1.2+), as dotted paths.</summary>
    public IReadOnlyList<string> ReplacePaths { get; init; } = [];

    public string? ActionReason { get; init; }

    public bool IsManaged { get; init; } = true;
}

/// <summary>
/// The parts of <c>terraform show -json &lt;planfile&gt;</c> Bauplan uses. Only documented fields of the
/// JSON output format (format_version 1.x) are read: resource_changes and configuration.
/// </summary>
public sealed class TerraformPlan
{
    public required string FormatVersion { get; init; }
    public string? TerraformVersion { get; init; }
    public required IReadOnlyList<ResourceChange> Changes { get; init; }
    public required Configuration Configuration { get; init; }

    public static TerraformPlan Parse(string json)
    {
        JsonNode? root;
        try
        {
            root = JsonNode.Parse(json, documentOptions: new JsonDocumentOptions { MaxDepth = 256 });
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException($"Not valid JSON: {ex.Message}", ex);
        }
        if (root is not JsonObject obj)
            throw new InvalidDataException("Not a Terraform plan: the JSON is not an object.");

        var format = obj["format_version"]?.GetValue<string>()
                     ?? throw new InvalidDataException("Not a Terraform plan: format_version is missing. Create the file with: terraform show -json plan.tfplan > plan.json");
        if (!format.StartsWith("1.", StringComparison.Ordinal))
            throw new InvalidDataException($"Unsupported plan format_version {format} (Bauplan reads 1.x).");
        if (obj["resource_changes"] is null && obj["planned_values"] is null && obj["values"] is not null)
            throw new InvalidDataException("This is a state file (terraform show -json without a plan), not a plan.");

        var changes = new List<ResourceChange>();
        foreach (var rc in obj["resource_changes"]?.AsArray() ?? [])
        {
            if (rc is not JsonObject r) continue;
            var change = r["change"] as JsonObject;
            var actions = change?["actions"]?.AsArray().Select(a => a!.GetValue<string>()).ToList() ?? [];
            changes.Add(new ResourceChange
            {
                Address = r["address"]?.GetValue<string>() ?? "",
                Type = r["type"]?.GetValue<string>() ?? "",
                Name = r["name"]?.GetValue<string>() ?? "",
                ModuleAddress = r["module_address"]?.GetValue<string>(),
                ProviderName = r["provider_name"]?.GetValue<string>() ?? "",
                IsManaged = (r["mode"]?.GetValue<string>() ?? "managed") == "managed",
                Action = ToAction(actions),
                CreateBeforeDestroy = actions is ["create", "delete"],
                Before = change?["before"] as JsonObject,
                After = change?["after"] as JsonObject,
                AfterUnknown = change?["after_unknown"] as JsonObject,
                ReplacePaths = (change?["replace_paths"] as JsonArray ?? []).Select(PathToString).ToList(),
                ActionReason = r["action_reason"]?.GetValue<string>(),
            });
        }

        return new TerraformPlan
        {
            FormatVersion = format,
            TerraformVersion = obj["terraform_version"]?.GetValue<string>(),
            Changes = changes,
            Configuration = Configuration.From(obj["configuration"] as JsonObject),
        };
    }

    internal static ChangeAction ToAction(IReadOnlyList<string> actions) => actions switch
    {
        ["no-op"] or [] => ChangeAction.NoOp,
        ["create"] => ChangeAction.Create,
        ["read"] => ChangeAction.Read,
        ["update"] => ChangeAction.Update,
        ["delete"] => ChangeAction.Delete,
        ["delete", "create"] or ["create", "delete"] => ChangeAction.Replace,
        _ => throw new InvalidDataException($"Unknown change actions [{string.Join(", ", actions)}]"),
    };

    // replace_paths entries are arrays of steps: ["site_config", 0, "name"] → site_config.0.name
    private static string PathToString(JsonNode? path) => path is JsonArray steps
        ? string.Join('.', steps.Select(s => s?.ToString() ?? ""))
        : path?.ToString() ?? "";
}

/// <summary>
/// The <c>configuration</c> section: what the code says, before evaluation. Needed because many values in a plan are
/// "known after apply", while the expression still shows where they come from (a constant, or a reference such as
/// <c>data.azurerm_subscription.current.id</c>).
/// </summary>
public sealed class Configuration
{
    private readonly Dictionary<string, JsonObject> expressions;

    private Configuration(Dictionary<string, JsonObject> expressions) => this.expressions = expressions;

    public static Configuration Empty { get; } = new([]);

    public static Configuration From(JsonObject? configuration)
    {
        var map = new Dictionary<string, JsonObject>(StringComparer.Ordinal);
        if (configuration?["root_module"] is JsonObject root)
            Collect(root, "", map);
        return new Configuration(map);
    }

    private static void Collect(JsonObject module, string prefix, Dictionary<string, JsonObject> map)
    {
        foreach (var r in module["resources"]?.AsArray() ?? [])
            if (r?["address"]?.GetValue<string>() is { } address && r["expressions"] is JsonObject e)
                map[prefix + address] = e;
        if (module["module_calls"] is JsonObject calls)
            foreach (var (name, call) in calls)
                if (call?["module"] is JsonObject child)
                    Collect(child, $"{prefix}module.{name}.", map);
    }

    /// <summary>References of an attribute (e.g. ["azurerm_key_vault.main.id", "azurerm_key_vault.main"]). Count/for_each indexes are ignored.</summary>
    public IReadOnlyList<string> References(string address, string attribute)
    {
        if (Expression(address, attribute) is not JsonObject e || e["references"] is not JsonArray refs) return [];
        return refs.Select(r => r!.GetValue<string>()).ToList();
    }

    /// <summary>True when the attribute is a literal in the code (constant_value), e.g. a hard-coded secret.</summary>
    public bool IsConstant(string address, string attribute) =>
        Expression(address, attribute) is JsonObject e && e.ContainsKey("constant_value");

    /// <summary>
    /// True when the attribute is written as a literal: a constant_value, or an expression without any reference
    /// (Terraform leaves out constant_value for sensitive literals). False for var.x, random_password.y.result, etc.
    /// </summary>
    public bool IsLiteral(string address, string attribute) =>
        Expression(address, attribute) is JsonObject e && (e.ContainsKey("constant_value") || e["references"] is not JsonArray { Count: > 0 });

    /// <summary>All configured resources whose attribute references the given address.</summary>
    public IEnumerable<string> ReferencedBy(string type, string attribute, string target)
    {
        var targetBase = StripIndex(target);
        foreach (var (address, e) in expressions)
        {
            if (!ResourceType(address).Equals(type, StringComparison.Ordinal)) continue;
            if (e[attribute]?["references"] is not JsonArray refs) continue;
            if (refs.Any(r => r?.GetValue<string>() is { } s && (s == targetBase || s.StartsWith(targetBase + ".", StringComparison.Ordinal))))
                yield return address;
        }
    }

    private JsonNode? Expression(string address, string attribute)
    {
        if (!expressions.TryGetValue(StripIndex(address), out var e)) return null;
        return e[attribute];
    }

    // azurerm_storage_account.logs["eu"] and module.app[0].azurerm_x.y are configured once, without the index
    internal static string StripIndex(string address) => System.Text.RegularExpressions.Regex.Replace(address, @"\[[^\]]*\]", "");

    private static string ResourceType(string address)
    {
        var parts = address.Split('.');
        // module.<name>.<type>.<name> → type is the second to last part
        return parts.Length >= 2 ? parts[^2] : "";
    }
}
