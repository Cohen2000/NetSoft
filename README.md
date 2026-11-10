# Software-Defined Networking Labs

Networking coursework covering OpenFlow controllers and programmable packet processing with P4. The exercises explore how routing and forwarding behaviour can be implemented in software.

## What is inside

- **[openflow/](openflow/):** Python/Ryu controller exercises, including routing and anycast forwarding with round-robin and flow-based variants.
- **[p4/](p4/):** P4 exercises for packet processing, including aggregation, IPv6 and protection/tunnelling behaviour.

## Start here

Open the exercise folders to read the controller or P4 source alongside its topology and configuration files. For example, [flow_controller.py](openflow/1.4/b/flow_controller.py) contains an OpenFlow controller and [protection.p4](p4/2.4/protection.p4) illustrates programmable data-plane logic.

**Tools:** Python, Ryu/OpenFlow, Mininet and P4. Running these labs requires the corresponding networking tools and exercise-specific configuration; this is a collection of lab exercises rather than a single installable application.
