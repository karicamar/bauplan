using System.Text;
using Bauplan.Core.Analysis;
using Bauplan.Core.Plan;
using Bauplan.Core.Policy;
using Bauplan.Core.Reporting;
using Bauplan.Core.Rules;

Console.OutputEncoding = Encoding.UTF8;

if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
    return Usage(args.Length == 0 ? 2 : 0);
if (args[0] == "--version")
{
    Console.WriteLine(ReportFormats.ToolVersion);
    return 0;
}
if (args[0] == "rules")
    return ListRules();

string? planPath = null;
string? source = null;
string? output = null;
string? ignoreFile = null;
var format = "console";
var failOn = Severity.High;
var newOnly = false;

try
{
    for (var i = 0; i < args.Length; i++)
    {
        switch (args[i])
        {
            case "--format" or "-f": format = args[++i].ToLowerInvariant(); break;
            case "--output" or "-o": output = args[++i]; break;
            case "--source" or "-s": source = args[++i]; break;
            case "--ignore-file": ignoreFile = args[++i]; break;
            case "--new-only": newOnly = true; break;
            case "--fail-on":
                var level = args[++i].ToLowerInvariant();
                failOn = level == "none" ? (Severity)99 : Enum.Parse<Severity>(level, ignoreCase: true);
                break;
            default:
                if (args[i].StartsWith('-')) { Console.Error.WriteLine($"Unknown option {args[i]}"); return Usage(2); }
                planPath = args[i];
                break;
        }
    }
}
catch (Exception ex) when (ex is IndexOutOfRangeException or ArgumentException)
{
    Console.Error.WriteLine("Invalid arguments: " + ex.Message);
    return Usage(2);
}

if (format is not ("console" or "json" or "markdown" or "md" or "sarif"))
{
    Console.Error.WriteLine($"Unknown format {format}");
    return Usage(2);
}
if (planPath is null || !File.Exists(planPath))
{
    Console.Error.WriteLine(planPath is null ? "Give the plan JSON: terraform show -json plan.tfplan > plan.json" : $"Not found: {planPath}");
    return 2;
}

TerraformPlan plan;
try
{
    plan = TerraformPlan.Parse(File.ReadAllText(planPath));
}
catch (InvalidDataException ex)
{
    Console.Error.WriteLine($"{planPath}: {ex.Message}");
    return 2;
}

var planDir = Path.GetDirectoryName(Path.GetFullPath(planPath))!;
var ignorePath = ignoreFile ?? Path.Combine(source ?? planDir, ".bauplan-ignore");
if (ignoreFile is not null && !File.Exists(ignoreFile))
{
    Console.Error.WriteLine($"Ignore file not found: {ignoreFile}");
    return 2;
}
var ignore = File.Exists(ignorePath) ? IgnoreList.Parse(File.ReadAllText(ignorePath)) : IgnoreList.Empty;

var result = new Analyzer().Analyze(plan, ignore);

// Paths in SARIF are relative to the current directory (the repository root in CI)
var locator = new SourceLocator(source ?? planDir, Directory.GetCurrentDirectory());
locator.Annotate(result);
var relativePlan = Path.GetRelativePath(Directory.GetCurrentDirectory(), Path.GetFullPath(planPath)).Replace('\\', '/');

var text = format switch
{
    "json" => ReportFormats.ToJson(result),
    "markdown" or "md" => ReportFormats.ToMarkdown(result),
    "sarif" => ReportFormats.ToSarif(result, relativePlan),
    _ => null,
};

if (text is null)
    ConsoleReport.Print(result, failOn, newOnly);
else if (output is not null)
{
    File.WriteAllText(output, text);
    Console.Error.WriteLine($"Report written to {output}");
}
else
    Console.WriteLine(text);

if (Environment.GetEnvironmentVariable("GITHUB_STEP_SUMMARY") is { Length: > 0 } summary)
    File.AppendAllText(summary, ReportFormats.ToMarkdown(result));

return result.Fails(failOn, newOnly) ? 1 : 0;

static int ListRules()
{
    foreach (var r in RuleCatalog.All)
    {
        Console.WriteLine($"{r.Id,-11} {r.Severity,-9} {r.Title}" + (r.Benchmark is null ? "" : $"  ({r.Benchmark})"));
        Console.WriteLine($"{"",-21}{string.Join(", ", r.Types.Order())}");
        Console.WriteLine();
    }
    Console.WriteLine($"{"DESTROY",-11} {"Critical",-9} Delete or replace of a resource that holds data, or of a resource group");
    return 0;
}

static int Usage(int code)
{
    Console.WriteLine("""
        Bauplan: security review of a Terraform plan for Azure (azurerm)

        Usage:
          terraform plan -out plan.tfplan && terraform show -json plan.tfplan > plan.json
          bauplan <plan.json> [options]
          bauplan rules                                   List the checks

        Options:
          -f, --format <console|json|markdown|sarif>     Output format (default: console)
          -o, --output <file>                            Write the report to a file
          -s, --source <folder>                          Terraform code, to point findings at file:line (default: the plan's folder)
              --fail-on <critical|high|medium|low|none>  Exit code 1 at this severity or above (default: high)
              --new-only                                 Fail only on findings this plan introduces (and on destruction)
              --ignore-file <file>                       Accepted risks (default: .bauplan-ignore in the source folder)

        Exit codes: 0 = OK, 1 = findings at or above --fail-on, 2 = error.

        The plan JSON contains every value Terraform knows, sensitive ones included: treat it like a secret
        (do not upload it as a build artifact). Bauplan never prints attribute values of secrets.
        """);
    return code;
}

static class ConsoleReport
{
    public static void Print(AnalysisResult r, Severity failOn, bool newOnly)
    {
        Console.WriteLine();
        Write($"  Bauplan {ReportFormats.ToolVersion}", ConsoleColor.White);
        Console.WriteLine($"  Plan: {r.Summary}" + (r.TerraformVersion is null ? "" : $"  (Terraform {r.TerraformVersion})"));
        Console.WriteLine();

        var destroy = r.ActiveDestructive.ToList();
        if (destroy.Count > 0)
        {
            Write("  Destroys\n", ConsoleColor.White);
            foreach (var d in destroy)
            {
                Write($"    {Label(d.Severity),-9}", Color(d.Severity));
                Write($"{d.Address}", d.Severity > Severity.Info ? ConsoleColor.White : ConsoleColor.Gray);
                Console.WriteLine($" {d.Message}");
                if (d.Source is { } s) Write($"             {s.File}:{s.Line}\n", ConsoleColor.DarkGray);
            }
            Console.WriteLine();
        }

        foreach (var (status, title) in new[] { (FindingStatus.New, "Introduced by this plan"), (FindingStatus.Existing, "Already present before this plan") })
        {
            var list = r.ActiveFindings.Where(f => f.Status == status).ToList();
            if (list.Count == 0) continue;
            Write($"  {title} ({list.Count})\n", ConsoleColor.White);
            foreach (var f in list)
            {
                Write($"    {Label(f.Severity),-9}", Color(f.Severity));
                Write($"{f.RuleId,-11}", ConsoleColor.DarkGray);
                Write($"{f.Address}", ConsoleColor.White);
                Console.WriteLine($": {f.Message}");
                if (f.Source is { } s) Write($"             {"",-11}{s.File}:{s.Line}\n", ConsoleColor.DarkGray);
            }
            Console.WriteLine();
        }

        if (r.Resolved.Count > 0)
        {
            Write($"  Fixed by this plan ({r.Resolved.Count})\n", ConsoleColor.White);
            foreach (var x in r.Resolved)
                Write($"    ✓ {x.RuleId,-11}{x.Address}: {x.Message}\n", ConsoleColor.Green);
            Console.WriteLine();
        }

        var accepted = r.Findings.Count(f => f.Suppressed) + r.Destructive.Count(d => d.Suppressed);
        if (accepted > 0) Write($"  accepted in .bauplan-ignore: {accepted}\n", ConsoleColor.DarkGray);
        foreach (var w in r.Warnings) Write($"  ! {w}\n", ConsoleColor.Yellow);

        var fails = r.Fails(failOn, newOnly);
        if (r.Worst is null || r.Worst == Severity.Info)
            Write("  ✓ Nothing to worry about in this plan\n", ConsoleColor.Green);
        else
            Write(fails ? $"  Failing: findings at or above --fail-on {failOn.ToString().ToLowerInvariant()}{(newOnly ? " (new only)" : "")}.\n"
                        : $"  Worst: {r.Worst}. Below --fail-on {failOn.ToString().ToLowerInvariant()}.\n", fails ? ConsoleColor.Red : ConsoleColor.Yellow);
        Console.WriteLine();
    }

    private static string Label(Severity s) => s.ToString().ToUpperInvariant();

    private static ConsoleColor Color(Severity s) => s switch
    {
        Severity.Critical => ConsoleColor.Magenta,
        Severity.High => ConsoleColor.Red,
        Severity.Medium => ConsoleColor.DarkYellow,
        Severity.Low => ConsoleColor.Yellow,
        _ => ConsoleColor.Gray,
    };

    private static void Write(string text, ConsoleColor color)
    {
        var old = Console.ForegroundColor;
        Console.ForegroundColor = color;
        Console.Write(text);
        Console.ForegroundColor = old;
    }
}
