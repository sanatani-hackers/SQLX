import sys
from pathlib import Path

path = Path('/data/data/com.termux/files/home/SQLX/sqlx/agent/agent.py')
content = path.read_text()

old_block = """            # ---- Tool-call round -------------------------------------------
            consecutive_tool_rounds += 1
            obs_refresh_counter += 1
            self.memory.messages.append(response.model_dump(exclude_none=True))

            for tool_call in response.tool_calls:"""

new_block = """            # ---- Tool-call round -------------------------------------------
            consecutive_tool_rounds += 1
            obs_refresh_counter += 1
            self.memory.messages.append(response.model_dump(exclude_none=True))
            
            # Print AI reasoning if present
            ai_text = getattr(response, "content", None)
            if ai_text and str(ai_text).strip():
                try:
                    from rich import print as rprint
                    from rich.panel import Panel
                    from rich.markdown import Markdown
                    rprint(Panel(Markdown(str(ai_text)), title="[bold blue]Agent Thinking[/bold blue]", border_style="blue"))
                except ImportError:
                    print(f"Agent Thinking: {ai_text}")

            for tool_call in response.tool_calls:"""

if old_block in content:
    content = content.replace(old_block, new_block)
    path.write_text(content)
    print("Patched agent.py to show AI reasoning successfully.")
else:
    print("Failed to find old_block in agent.py.")
    sys.exit(1)
