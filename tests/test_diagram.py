import unittest

from provisionguard.diagram import MAX_NODES, build_prompt, diagram_review, diagram_section, render, wants_diagram
from provisionguard.plan_parser import ResourceChange


def rc(address, action="create", after=None):
    rtype, name = address.split(".")[0], address.split(".")[1].split("[")[0]
    actions = {"create": ["create"], "update": ["update"], "replace": ["delete", "create"], "no-op": ["no-op"]}[action]
    return ResourceChange(address, rtype, name, actions, {} if action != "create" else None, after or {}, {})


def demo_changes():
    changes = [rc("aws_vpc.main", after={"cidr_block": "10.20.0.0/16"}),
               rc("aws_subnet.public[0]"), rc("aws_subnet.public[1]"),
               rc("aws_subnet.private[0]"), rc("aws_subnet.private[1]"),
               rc("aws_internet_gateway.main"), rc("aws_nat_gateway.main"),
               rc('aws_instance.this["bastion"]', after={"instance_type": "t3.micro"}),
               rc('aws_instance.this["app-1"]', after={"instance_type": "t3.medium"}),
               rc('aws_instance.this["app-2"]', after={"instance_type": "t3.medium"}),
               rc("aws_db_instance.main", after={"instance_class": "db.m5.large", "engine": "postgres"}),
               rc("aws_iam_role.eks_node", action="replace"),
               rc("aws_route_table_association.public[0]", action="no-op")]
    return changes


DIAGRAM = {
    "summary": "A dev VPC with a bastion in public subnets and apps plus Postgres in private subnets.",
    "groups": [{"id": "vpc", "label": "VPC 10.20.0.0/16", "parent": ""},
               {"id": "pub", "label": "Public subnets", "parent": "vpc"},
               {"id": "priv", "label": "Private subnets", "parent": "vpc"}],
    "nodes": [
        {"id": "net", "label": "Internet", "group": "", "external": True, "resources": []},
        {"id": "bastion", "label": "bastion · t3.micro", "group": "pub", "external": False,
         "resources": ['aws_instance.this["bastion"]']},
        {"id": "apps", "label": "app ×2 · t3.medium", "group": "priv", "external": False,
         "resources": ['aws_instance.this["app-1"]', 'aws_instance.this["app-2"]']},
        {"id": "db", "label": "Postgres · db.m5.large", "group": "priv", "external": False,
         "resources": ["aws_db_instance.main"]},
        {"id": "role", "label": "EKS node role", "group": "", "external": False, "resources": ["aws_iam_role.eks_node"]},
        {"id": "assoc", "label": "routes", "group": "pub", "external": False,
         "resources": ["aws_route_table_association.public"]},
        {"id": "ghost", "label": "Lambda that doesn't exist", "group": "priv", "external": False,
         "resources": ["aws_lambda_function.ghost"]},
    ],
    "edges": [{"from": "net", "to": "bastion", "label": "SSH 22"},
              {"from": "bastion", "to": "apps", "label": "SSH"},
              {"from": "apps", "to": "db", "label": "5432"},
              {"from": "apps", "to": "ghost", "label": "invoke"}],
}


class DiagramTest(unittest.TestCase):
    def test_when_to_draw(self):
        self.assertTrue(wants_diagram(demo_changes()))                               # many changes
        self.assertTrue(wants_diagram([rc("aws_subnet.a", action="update")]))       # network change
        self.assertFalse(wants_diagram([rc("aws_iam_role.x", action="update")]))    # small, not network
        self.assertFalse(wants_diagram([rc("aws_vpc.main", action="no-op")]))       # nothing changes

    def test_render_validates_against_the_plan(self):
        mermaid = render(DIAGRAM, demo_changes())
        print("\n" + mermaid)
        self.assertNotIn("Lambda", mermaid)          # invented box dropped
        self.assertNotIn("invoke", mermaid)          # and the arrow to it
        self.assertIn('subgraph g1["VPC 10.20.0.0/16"]', mermaid)
        self.assertIn('  subgraph g2["Public subnets"]', mermaid)  # nested inside the VPC
        self.assertIn('n1(("Internet"))', mermaid)
        self.assertIn("n1 -->|SSH 22| n2", mermaid)
        self.assertIn("class n2,n3,n4 create", mermaid)
        self.assertIn("class n5 destroy", mermaid)    # the replaced role
        self.assertIn("class n6 unchanged", mermaid)  # a no-op shown as context
        self.assertIn("class n1 external", mermaid)

    def test_labels_cannot_break_the_syntax(self):
        evil = {"groups": [], "edges": [], "summary": "",
                "nodes": [{"id": "x", "label": 'db"]; click n1 call alert() %%', "group": "", "external": False,
                           "resources": ["aws_db_instance.main"]}]}
        mermaid = render(evil, demo_changes())
        self.assertIn('n1["db click n1 call alert %%"]', mermaid)

    def test_nothing_valid_means_no_diagram(self):
        only_ghosts = dict(DIAGRAM, nodes=[DIAGRAM["nodes"][0], DIAGRAM["nodes"][-1]])
        self.assertIsNone(render(only_ghosts, demo_changes()))

    def test_node_cap(self):
        many = dict(DIAGRAM, nodes=[{"id": f"n{i}", "label": "x", "group": "", "external": False,
                                     "resources": ["aws_vpc.main"]} for i in range(50)], edges=[])
        self.assertEqual(render(many, demo_changes()).count('["x"]'), MAX_NODES)

    def test_section(self):
        text = diagram_section({}, demo_changes(), ask=lambda system, prompt, schema: DIAGRAM)
        self.assertIn("### 🗺️ Architecture", text)
        # The one-line summary goes to the top of the comment, under the verdict.
        review = diagram_review({}, demo_changes(), ask=lambda system, prompt, schema: DIAGRAM)
        self.assertEqual(review.lead, "🗺️ **This change:** " + DIAGRAM["summary"])
        self.assertNotIn(DIAGRAM["summary"], text)
        self.assertIn("<details open><summary>Diagram ·", text)  # expanded by default, still collapsible
        self.assertIn('```mermaid\n%%{init: {"flowchart": {"rankSpacing": 35', text)  # spacing first
        self.assertIn("\nflowchart LR\n", text)                                         # wide, not tall

    def test_section_is_left_out_when_not_useful_or_ai_fails(self):
        self.assertEqual(diagram_section({}, [rc("aws_iam_role.x", action="update")], ask=lambda *a: DIAGRAM), "")
        self.assertEqual(diagram_section({}, demo_changes(), ask=lambda *a: None), "")

    def test_prompt(self):
        prompt = build_prompt(demo_changes(), "resource {}")
        self.assertIn('aws_instance.this["bastion"] | create | instance_type=t3.micro', prompt)
        self.assertIn("aws_db_instance.main | create | instance_class=db.m5.large, engine=postgres", prompt)
        self.assertIn("aws_route_table_association.public[0] | no-op", prompt)
        self.assertIn("<terraform>\nresource {}\n</terraform>", prompt)


if __name__ == "__main__":
    unittest.main()
