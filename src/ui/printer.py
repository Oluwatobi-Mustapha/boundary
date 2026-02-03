from rich.console import Console
from rich.table import Table
from rich import box
from datetime import datetime
from src.models.request import AccessRequest
from src.core.engine import EvaluationResult

def print_verdict(req: AccessRequest, res: EvaluationResult):
    """
    Renders a high-fidelity table showing the request details and the policy decision.
    Handles timestamp formatting and conditional coloring.
    """
    console = Console()
    
    # 1. Create a Table with sections
    table = Table(title="Boundary Access Request Audit", box=box.ROUNDED, expand=True)
    
    # 2. Add Columns
    table.add_column("Component", style="cyan", no_wrap=True, width=20)
    table.add_column("Details", style="white")
    
    # 3. Request Context Section (Who/Where)
    table.add_section()
    table.add_row("[bold]Request Context[/]", "")
    table.add_row("Request ID", req.request_id)
    table.add_row("Principal", f"{req.principal_id} ({req.principal_type})")
    table.add_row("Target Account", req.account_id)
    
    # SECURITY UPDATE: Show both Name (Readability) and ARN (Auditability)
    perm_display = f"[bold]{req.permission_set_name}[/]\n[dim]{req.permission_set_arn}[/]"
    table.add_row("Permission Set", perm_display)

    # 4. Timing Section (When)
    table.add_section()
    table.add_row("[bold]Timing[/]", "")
    
    # Helper to format timestamps to readable strings
    def fmt_time(ts):
        return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')

    table.add_row("Requested At", fmt_time(req.requested_at))
    
    if res.effect == "ALLOW":
        duration_str = f"{res.effective_duration_hours} hours"
        if res.was_capped:
            duration_str += " [bold yellow](Capped by Policy)[/]"
        table.add_row("Approved Duration", duration_str)
        if res.effective_expires_at:
             table.add_row("Access Expires", fmt_time(res.effective_expires_at))

    # 5. Verdict Section (The Decision)
    table.add_section()
    table.add_row("[bold]Decision[/]", "")
    
    if res.effect == "ALLOW":
        verdict_style = "bold green"
        emoji = "✅"
    else:
        verdict_style = "bold red"
        emoji = "🚫"
        
    table.add_row("Final Verdict", f"[{verdict_style}]{emoji} {res.effect}[/]")
    table.add_row("Reason", res.reason)
    table.add_row("Matched Rule", res.rule_id or "[dim]N/A[/]")
    
    if res.approval_required:
         table.add_row("Approval Workflow", f"Triggered -> Channel: {res.approval_channel}")

    # 6. Print it
    console.print(table)