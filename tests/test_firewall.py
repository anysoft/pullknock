import unittest

from pullknock.config import FirewallConfig, GrantConfig, PortConfig
from pullknock.firewall import FirewalldBackend


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

        self.assertEqual(len(results), 1)
        self.assertEqual(
            results[0].args,
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


if __name__ == "__main__":
    unittest.main()
