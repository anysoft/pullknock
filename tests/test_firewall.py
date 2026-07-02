import unittest

from pullknock.config import FirewallConfig, GrantConfig, PortConfig
from pullknock.firewall import FirewalldBackend, NftablesBackend


class FirewallTest(unittest.TestCase):
    def test_firewalld_dry_run_uses_local_grant_values_only(self):
        backend = FirewalldBackend(
            FirewallConfig(firewall_cmd="/usr/bin/firewall-cmd", default_zone="public"),
            dry_run=True,
        )
        grant = GrantConfig(
            id="ssh",
            description="ssh",
            allowed_principals=("jonhy",),
            ports=(PortConfig(protocol="tcp", port=22),),
            max_timeout_seconds=60,
            zone="trusted",
            allow_source_cidrs=("0.0.0.0/0",),
        )

        results = backend.open_grant(grant, source_ip="203.0.113.7", timeout_seconds=30)

        self.assertEqual(len(results), 2)
        self.assertEqual(
            results[0].args,
            [
                "/usr/bin/firewall-cmd",
                "--zone",
                "trusted",
                "--remove-rich-rule",
                'rule family="ipv4" source address="203.0.113.7" port protocol="tcp" port="22" accept',
            ],
        )
        self.assertEqual(
            results[1].args,
            [
                "/usr/bin/firewall-cmd",
                "--zone",
                "trusted",
                "--add-rich-rule",
                'rule family="ipv4" source address="203.0.113.7" port protocol="tcp" port="22" accept',
                "--timeout",
                "30",
            ],
        )

    def test_nftables_dry_run_adds_timed_source_to_port_set(self):
        backend = NftablesBackend(
            FirewallConfig(
                backend="nftables",
                nft_cmd="/usr/sbin/nft",
                nft_family="inet",
                nft_table="pullknock",
                nft_set_prefix="pk",
            ),
            dry_run=True,
        )
        grant = GrantConfig(
            id="ssh",
            description="ssh",
            allowed_principals=("jonhy",),
            ports=(PortConfig(protocol="tcp", port=22),),
            max_timeout_seconds=60,
            zone=None,
            allow_source_cidrs=("0.0.0.0/0",),
        )

        results = backend.open_grant(grant, source_ip="203.0.113.7", timeout_seconds=30)

        self.assertEqual(
            [result.args for result in results],
            [
                ["/usr/sbin/nft", "add", "table", "inet", "pullknock"],
                [
                    "/usr/sbin/nft",
                    "add",
                    "set",
                    "inet",
                    "pullknock",
                    "pk_tcp_22_ipv4",
                    "{",
                    "type",
                    "ipv4_addr;",
                    "flags",
                    "timeout;",
                    "}",
                ],
                [
                    "/usr/sbin/nft",
                    "add",
                    "element",
                    "inet",
                    "pullknock",
                    "pk_tcp_22_ipv4",
                    "{",
                    "203.0.113.7",
                    "timeout",
                    "30s",
                    "}",
                ],
            ],
        )


if __name__ == "__main__":
    unittest.main()
