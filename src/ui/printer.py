from rich.console import Console
from rich.table import Table
from rich import box
from src.models.request import AccessRequest
from src.core.engine import EvaluationResult

def print_verdict(req: AccessRequest, res: EvaluationResult):
    console = Console()
    
    # 1. Create a Table for the Decision
    table = Table(title="Boundary Access Request Audit", box=box.ROUNDED)
    
    # 2. Add Columns
    table.add_column("Component", style="cyan", no_wrap=True)
    table.add_column("Details", style="magenta")
    
    # 3. Add Rows (The Facts)
    table.add_row("Request ID", req.request_id)
    table.add_row("User (Principal)", req.principal_id)
    table.add_row("Target Account", req.account_id)
    table.add_row("Permission Set", req.permission_set_arn) # We will see the ARN here since Mock didn't resolve name yet
    
    # 4. The Verdict Logic (Coloring)
    if res.effect == "ALLOW":
        verdict_style = "bold green"
        emoji = "✅"
    else:
        verdict_style = "bold red"
        emoji = "🚫"
        
    table.add_row("Final Verdict", f"[{verdict_style}]{emoji} {res.effect}[/]")
    table.add_row("Reason", res.reason)
    table.add_row("Matched Rule", res.rule_id or "N/A")
    
    # 5. Print it
    console.print(table)