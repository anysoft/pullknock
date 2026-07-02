"""Generate multi-server PullKnock configs from an inventory YAML."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import click
import yaml

from .errors import ConfigError
from .util import expand_path


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("inventory_path")
@click.argument("output_dir")
@click.option("--force", is_flag=True, help="Overwrite existing generated files.")
def main(inventory_path: str, output_dir: str, force: bool) -> None:
    """Generate agent and CLI YAML configs for multiple servers."""
    try:
        inventory = _load_inventory(inventory_path)
        written = generate_configs(inventory, Path(expand_path(output_dir)), force=force)
    except ConfigError as exc:
        raise click.ClickException(str(exc)) from exc
    for path in written:
        click.echo(str(path))


def generate_configs(inventory: dict[str, Any], output_dir: Path, *, force: bool = False) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    agents_dir = output_dir / "agents"
    agents_dir.mkdir(parents=True, exist_ok=True)

    defaults = _mapping(inventory.get("defaults", {}), "defaults")
    agent_defaults = _mapping(defaults.get("agent", {}), "defaults.agent")
    cli_defaults = _mapping(defaults.get("cli", {}), "defaults.cli")
    publishers = _mapping(inventory.get("publishers", {}), "publishers")
    users = _mapping(inventory.get("users", {}), "users")
    groups = _mapping(inventory.get("groups", {}), "groups")
    grant_templates = _mapping(inventory.get("grant_templates", {}), "grant_templates")
    servers = _mapping(inventory.get("servers"), "servers")

    cli_config = {
        "defaults": cli_defaults,
        "publishers": publishers,
        "targets": {},
    }
    written: list[Path] = []
    for server_name, raw_server in servers.items():
        if not isinstance(server_name, str) or not server_name:
            raise ConfigError("servers keys must be non-empty strings")
        server_data = _mapping(raw_server, f"servers.{server_name}")
        server_section = dict(_mapping(agent_defaults.get("server", {}), "defaults.agent.server"))
        server_section.update(_mapping(server_data.get("server", {}), f"servers.{server_name}.server"))
        server_section.setdefault("id", server_data.get("id", server_name))

        grants = _merge_grants(
            grant_templates,
            _mapping(server_data.get("grants"), f"servers.{server_name}.grants"),
            scope=f"servers.{server_name}.grants",
        )
        agent_config = {
            "server": server_section,
            "security": _merged_mapping(agent_defaults.get("security", {}), server_data.get("security", {})),
            "firewall": _merged_mapping(agent_defaults.get("firewall", {}), server_data.get("firewall", {})),
            "audit": _merged_mapping(agent_defaults.get("audit", {}), server_data.get("audit", {})),
            "groups": _merged_mapping(groups, server_data.get("groups", {})),
            "users": _merged_mapping(users, server_data.get("users", {})),
            "grants": grants,
        }
        agent_path = agents_dir / f"{server_name}.agent.yaml"
        _write_yaml(agent_path, agent_config, force=force)
        written.append(agent_path)

        publisher_name = server_data.get("publisher")
        if not publisher_name and publishers:
            publisher_name = next(iter(publishers))
        if publisher_name:
            for grant_id in grants:
                target_name = f"{server_name}-{grant_id}"
                cli_config["targets"][target_name] = {
                    "target": server_section["id"],
                    "grant_id": grant_id,
                    "publisher": publisher_name,
                }

    cli_path = output_dir / "cli-config.yaml"
    _write_yaml(cli_path, cli_config, force=force)
    written.append(cli_path)
    return written


def _load_inventory(path: str) -> dict[str, Any]:
    try:
        data = yaml.safe_load(Path(expand_path(path)).read_text(encoding="utf-8")) or {}
    except OSError as exc:
        raise ConfigError(f"cannot_read_inventory: {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid_inventory_yaml: {path}: {exc}") from exc
    return _mapping(data, "root")


def _merge_grants(templates: dict[str, Any], grants: dict[str, Any], *, scope: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for grant_id, raw_grant in grants.items():
        grant = dict(_mapping(raw_grant, f"{scope}.{grant_id}"))
        template_name = grant.pop("template", None)
        if template_name is None:
            result[grant_id] = grant
            continue
        if not isinstance(template_name, str) or template_name not in templates:
            raise ConfigError(f"unknown_grant_template: {scope}.{grant_id}.template={template_name}")
        merged = dict(_mapping(templates[template_name], f"grant_templates.{template_name}"))
        merged.update(grant)
        result[grant_id] = merged
    return result


def _merged_mapping(base: Any, overlay: Any) -> dict[str, Any]:
    result = dict(_mapping(base or {}, "base"))
    result.update(_mapping(overlay or {}, "overlay"))
    return result


def _mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError(f"{name} must be a mapping")
    return value


def _write_yaml(path: Path, data: dict[str, Any], *, force: bool) -> None:
    if path.exists() and not force:
        raise ConfigError(f"refusing_to_overwrite: {path} (use --force)")
    path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")


if __name__ == "__main__":
    main()
