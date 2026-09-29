import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import port_forwarder as pf  # noqa: E402


class AnnouncedPorts(unittest.TestCase):
    def test_common_dev_server_banners(self):
        self.assertEqual(pf.announced_ports("  VITE v5  ready\n  ➜  Local:   http://localhost:5173/\n"), [5173])
        self.assertEqual(pf.announced_ports("Listening at http://127.0.0.1:8000 (Press CTRL+C to quit)"), [8000])
        self.assertEqual(pf.announced_ports("Serving on 0.0.0.0:3000"), [3000])
        self.assertEqual(pf.announced_ports("bound to [::1]:4000, [::]:4001"), [4000, 4001])
        self.assertEqual(pf.announced_ports("http://LOCALHOST:9000"), [9000])

    def test_ports_are_reported_once_in_order(self):
        self.assertEqual(pf.announced_ports("localhost:5173\nlocalhost:8000\nlocalhost:5173"), [5173, 8000])

    def test_rejects_non_loopback_malformed_and_system_ports(self):
        for line in [
            "http://192.168.1.5:5173/",
            "http://mylocalhost:5173/",
            "http://10.0.0.0:5173/",
            "localhost:0",
            "localhost:80",
            "localhost:70000",
            "localhost:123456",
            "localhost:3000abc",
            "localhost: 3000",
            "time 12:30:45",
        ]:
            self.assertEqual(pf.announced_ports(line), [], line)


class ChooseLocalPort(unittest.TestCase):
    def test_prefers_remembered_then_same_then_nearby(self):
        self.assertEqual(pf.choose_local_port(5173, 6000, lambda port: True), 6000)
        self.assertEqual(pf.choose_local_port(5173, None, lambda port: True), 5173)
        self.assertEqual(pf.choose_local_port(5173, 6000, lambda port: port not in (6000, 5173)), 5174)

    def test_gives_up_after_nearby_ports(self):
        self.assertIsNone(pf.choose_local_port(5173, None, lambda port: False))
        self.assertEqual(pf.choose_local_port(5173, None, lambda port: port == 5173 + pf.NEARBY_PORTS), 5173 + pf.NEARBY_PORTS)


class FormatToken(unittest.TestCase):
    def test_marks_differing_local_ports(self):
        self.assertEqual(pf.format_token([(8000, 8001), (5173, 5173)]), "⇄ 5173 8000→8001")
        self.assertEqual(pf.format_token([]), "")

    def test_stays_within_the_token_limit(self):
        token = pf.format_token([(port, port) for port in range(10000, 10100)])
        self.assertLessEqual(len(token), pf.TOKEN_MAX_CHARS)
        self.assertTrue(token.startswith("⇄ 10000 10001"))


class SplitSections(unittest.TestCase):
    def test_splits_at_marker_lines_only(self):
        output = "noise\n@@abc workspaces\n{}\n@@abc read w1:p1\nline @@abc read x\nmore\n@@abc read w1:p2\n"
        self.assertEqual(
            pf.split_sections(output, "abc"),
            {"workspaces": "{}", "read w1:p1": "line @@abc read x\nmore", "read w1:p2": ""},
        )


class PlanConfig(unittest.TestCase):
    def test_empty_config_gets_both_blocks(self):
        addition, _ = pf.plan_config("")
        self.assertIn("[ui.sidebar.spaces]", addition)
        self.assertIn(pf.POPUP_KEY, addition)

    def test_second_run_adds_nothing(self):
        addition, _ = pf.plan_config("")
        again, _ = pf.plan_config("onboarding = false\n" + addition)
        self.assertEqual(again, "")

    def test_existing_space_rows_are_not_touched(self):
        for text in [
            "[ui.sidebar.spaces]\nrows = [[\"workspace\"]]\n",
            "[ ui.sidebar.spaces ]\nrow_gap = 1\n",
            "[ui.sidebar]\nspaces = { rows = [[\"workspace\"]] }\n",
            "[ui.sidebar]\nspaces.rows = [[\"workspace\"]]\n",
            "[ui]\nsidebar.spaces.rows = [[\"workspace\"]]\n",
            "ui.sidebar.spaces.rows = [[\"workspace\"]]\n",
        ]:
            addition, messages = pf.plan_config(text)
            self.assertNotIn("[ui.sidebar.spaces]", addition, text)
            self.assertIn("not changed", messages[0], text)

    def test_other_sidebar_settings_do_not_block_the_row(self):
        addition, _ = pf.plan_config("[ui.sidebar.agents]\nrow_gap = 0\n[ui]\nmouse_scroll_lines = 1\n")
        self.assertIn("[ui.sidebar.spaces]", addition)

    def test_a_key_already_in_use_is_not_bound_again(self):
        addition, messages = pf.plan_config('[[keys.command]]\nkey = "prefix+shift+p"\ntype = "pane"\ncommand = "htop"\n')
        self.assertNotIn("[[keys.command]]", addition)
        self.assertIn("already bound", messages[1])


if __name__ == "__main__":
    unittest.main()
