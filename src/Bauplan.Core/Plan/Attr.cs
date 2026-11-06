using System.Globalization;
using System.Text.Json.Nodes;

namespace Bauplan.Core.Plan;

/// <summary>
/// The state of one resource as a rule sees it: its attribute values and which of them are unknown until apply.
/// Nested blocks are arrays in the plan JSON (<c>site_config: [{...}]</c>); paths step into the first element.
/// </summary>
public sealed class ResourceState
{
    public ResourceState(string address, string type, JsonObject values, JsonObject? unknown = null)
    {
        Address = address;
        Type = type;
        Values = values;
        Unknown = unknown;
    }

    public string Address { get; }
    public string Type { get; }
    public JsonObject Values { get; }
    public JsonObject? Unknown { get; }

    public JsonNode? Get(string path) => Navigate(Values, path);

    /// <summary>True when the value is only known after apply: a rule cannot judge it from the plan.</summary>
    public bool IsUnknown(string path) => Navigate(Unknown, path) is JsonValue v && v.TryGetValue<bool>(out var b) && b;

    public string? String(string path) => Get(path) is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;

    /// <summary>A boolean, or the provider default when the attribute is not set.</summary>
    public bool Bool(string path, bool defaultValue) => Get(path) switch
    {
        JsonValue v when v.TryGetValue<bool>(out var b) => b,
        _ => defaultValue,
    };

    public int? Int(string path) => Get(path) switch
    {
        JsonValue v when v.TryGetValue<int>(out var i) => i,
        JsonValue v when v.TryGetValue<double>(out var d) => (int)d,
        JsonValue v when v.TryGetValue<string>(out var s) && int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var p) => p,
        _ => null,
    };

    public IReadOnlyList<string> Strings(string path) => Get(path) switch
    {
        JsonArray a => a.Select(n => n is JsonValue v && v.TryGetValue<string>(out var s) ? s : null).OfType<string>().ToList(),
        JsonValue v when v.TryGetValue<string>(out var s) => [s],
        _ => [],
    };

    /// <summary>The objects of a repeated block (security_rule, ip_rule, ...), each as its own state.</summary>
    public IReadOnlyList<ResourceState> Blocks(string path)
    {
        var node = Navigate(Values, path);
        if (node is not JsonArray items) return [];
        var unknown = Navigate(Unknown, path) as JsonArray;
        var list = new List<ResourceState>();
        for (var i = 0; i < items.Count; i++)
            if (items[i] is JsonObject o)
                list.Add(new ResourceState($"{Address}.{path}[{i}]", Type, o, unknown is not null && i < unknown.Count ? unknown[i] as JsonObject : null));
        return list;
    }

    /// <summary>True when a nested block is present (an empty list means the block is not configured).</summary>
    public bool HasBlock(string path) => Navigate(Values, path) is JsonArray { Count: > 0 };

    internal static JsonNode? Navigate(JsonNode? node, string path)
    {
        var steps = path.Split('.');
        for (var i = 0; i < steps.Length && node is not null; i++)
        {
            if (node is JsonArray arr)
            {
                if (arr.Count == 0) return null;
                node = arr[0];
            }
            node = node is JsonObject o ? o[steps[i]] : null;
        }
        return node;
    }
}
