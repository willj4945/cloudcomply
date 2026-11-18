# DoD Cloud Computing SRG Impact Levels

The [DoD Cloud Computing Security Requirements Guide (CC SRG)](https://public.cyber.mil/dccs/) defines **Impact Levels (ILs)** based on how sensitive the data in a cloud system is. A DoD **Mission Owner** (MO) deploying on AWS targets a specific IL, and the set of controls they're responsible for grows with it.

| Impact Level | Typical data | AWS regions (typical) |
|---|---|---|
| **IL2** | Public or non-critical mission information | Commercial and GovCloud (US) |
| **IL4** | Controlled Unclassified Information (CUI) | GovCloud (US) |
| **IL5** | Higher-sensitivity CUI, mission-critical information, National Security Systems | GovCloud (US) |
| **IL6** | Classified up to SECRET | AWS Secret Region |

Check current provisional authorizations for each AWS service and region with your authorizing official. They change over time.

## How cloudcomply uses ILs

Each finding has a `min_impact_level`: the **lowest** IL at which the control is required. Levels stack, so a control required at IL2 is also in scope at IL4, IL5 and IL6.

- The **findings browser** IL filter (`[` / `]`) shows every control required at or below the selected level.
- The **dashboard** shows an IL5-scoped readiness score next to the overall NIST score.

## Current limitation

!!! warning "Live data is always IL2 today"
    AWS Security Hub has no concept of DoD Impact Levels, and the NIST → SRG crosswalk isn't built into cloudcomply yet. Until it is, every **live** finding reports `min_impact_level: IL2`, so the IL filter and IL5 score match the overall score.

    Demo mode (`--demo`) shows what IL-scoped scoring will look like once the crosswalk ships. See the [roadmap](../project/roadmap.md).
