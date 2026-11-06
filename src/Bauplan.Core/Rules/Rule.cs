using Bauplan.Core.Plan;

namespace Bauplan.Core.Rules;

public enum Severity
{
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// <summary>One problem a rule found in one resource.</summary>
/// <param name="Key">Identity of the problem inside the resource (e.g. the NSG rule name), so before/after can be compared.</param>
/// <param name="Attribute">The attribute to change, as a dotted path.</param>
public sealed record Issue(string Message, string Attribute, string Key = "", Severity? SeverityOverride = null);

/// <summary>What a rule may look at besides the resource itself.</summary>
public sealed class RuleContext
{
    public RuleContext(TerraformPlan plan) => Plan = plan;

    public TerraformPlan Plan { get; }
    public Configuration Configuration => Plan.Configuration;

    /// <summary>Resources that will exist after apply (everything except deletes).</summary>
    public IEnumerable<ResourceChange> Remaining => Plan.Changes.Where(c => c.IsManaged && c.Action != ChangeAction.Delete);
}

/// <summary>A misconfiguration check on one or more resource types.</summary>
public abstract class Rule
{
    public abstract string Id { get; }
    public abstract string Title { get; }
    public abstract Severity Severity { get; }

    /// <summary>network, encryption, identity, secrets, data-protection, logging</summary>
    public abstract string Category { get; }

    /// <summary>Microsoft cloud security benchmark control, where one fits.</summary>
    public virtual string? Benchmark => null;

    public abstract string Why { get; }
    public abstract string Fix { get; }
    public abstract IReadOnlySet<string> Types { get; }

    public abstract IEnumerable<Issue> Evaluate(ResourceState resource, RuleContext context);
}

public static class RuleCatalog
{
    public static IReadOnlyList<Rule> All { get; } =
    [
        new NsgOpenToInternetRule(),
        new DatabaseFirewallOpenRule(),
        new StoragePublicBlobRule(),
        new StorageNetworkRule(),
        new StorageSharedKeyRule(),
        new TlsMinimumRule(),
        new HttpsOnlyRule(),
        new AppServiceHardeningRule(),
        new PlaintextAppSecretRule(),
        new HardcodedSecretRule(),
        new KeyVaultPurgeProtectionRule(),
        new KeyVaultNetworkRule(),
        new SqlEntraAuthRule(),
        new PublicDatabaseRule(),
        new PrivilegedRoleAssignmentRule(),
        new AksHardeningRule(),
        new VmPasswordAuthRule(),
        new MissingDiagnosticsRule(),
    ];

    public static Rule? Get(string id) => All.FirstOrDefault(r => r.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
}
