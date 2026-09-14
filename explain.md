If you tell me what the objective is I can definitely provide some advice on how to structure an agentic system!

Also, it could be useful if rather than creating a new alert for every piece of TI, which can become a burden on the defender adding costs with every little change of tool or technique, if instead you had some of these behavioral indicators and used TI to verify coverage of the behavior (and improve the detection if not covered), then it would be less of a catch-up game with the burden on the defender and alerts more understandable. It puts the burden on the attacker to change behavior and create new methods, rather than on the defender to keep up with all the latest tooling (which ultimately slows down searches through volume and increases costs)
https://attack.mitre.org/detectionstrategies/
Detection Strategies | MITRE ATT&CK®
 
A couple dumps on the philosophical differences and why they both work but complement each other:

The main failure mode for behavioral is a false positive. The main failure mode for artifacts is a false negative. Behavioral investigations are more explainable where artifact investigations can end being more along the lines of “looks benign to me”.

**Assumptions**

*Enumeration Approach:*

- Adversary tooling repeats across victims; what hit someone else will hit you

- Detection value is countable, so coverage can be measured by volume

- Precision is the scarce resource; analyst attention is what you're protecting

- Intel supply keeps pace with adversary rotation

*Behavior Approach:*

- Objectives are more stable than implementations, so invariants exist at the objective layer

- Your telemetry reaches the chokepoints, and you can baseline normal well enough to make noise tractable

- The abstraction ladder can be climbed empirically — you can learn the implementation space

- Analyst tolerance for false positives is available and sustainable

**Tradeoffs**

| Axis | Enumeration | Behavior |

|---|---|---|

| Who pays for change | You, per rotation | Adversary, per redesign |

| Error mode | False negatives, known and priced in | False positives, plus silent decay into false confidence |

| Coverage claim | Provable but narrow | Broad but unprovable without validation |

| Scaling | Linear in intel volume | Linear in environment complexity |

| Refresh clock | Campaign | Platform epoch |

| Prerequisite | Feed ingestion | Telemetry depth, baselining, purple team |

| Time to value | Immediate | Slow, front-loaded |

| Failure visibility | Obvious (nothing fires) | Invisible (rule drifted, still green) |

| Unique capability | Retro-hunt, block, attribute | Catch first-seen tradecraft |

The load-bearing one: enumeration buys certainty about a small area, behavior buys uncertainty about a large one. That's why they're complements at different layers rather than rivals — and why the behaviorist owes validation as the price of the larger claim.


Why do most cyber defenders all go down the artifact enumeration route and resist the behavioral?

Because every incentive in the environment rewards it, and the counter-evidence is structurally invisible.

**The feedback loop is legible.** Ship an atomic, it either fires cleanly or sits silent. Ship a behavioral rule, get 200 alerts, spend three weeks tuning, and never learn whether it would have caught anything. One produces closure, the other produces ambiguity — and the false negatives that would prove the atomic approach wrong never announce themselves. You don't get an alert for the detection you didn't write.

**It's the only thing that's countable.** "We ingested 40,000 indicators, coverage up 12%" is a metric a board understands. "We have 30 rules but they sit on chokepoints" requires the audience to already accept the philosophy. Enumeration is legible to non-practitioners; behavior requires trust in judgment nobody has yet earned.

**Vendors sell the artifact model.** Feeds, TIPs, and SIEM licensing all monetize volume. Nobody sells "write fewer, better detections" because there's no recurring revenue in it. The tooling shapes the philosophy before anyone chooses one.

**It has no prerequisites.** Enumeration works on day one with a feed and a SIEM. Behavioral detection presupposes telemetry depth, a baseline of normal, and enough environmental knowledge to know that this scheduled task is the backup agent. Novices don't have that yet — so enumeration isn't just easier, it's the only option actually available to them. Sequencing.

**Anxiety asymmetry.** New intel drops feel like an open loop. Writing the rule closes it. Behavioral coverage never gives you that feeling of being current, and "we're covered because we watch the chokepoints" is psychologically harder to hold than a checklist.

**Nobody is trained out of it.** Certs and SOC onboarding teach IOC triage and playbooks. Behavioral detection is taught mainly by getting burned — living through an incident where every artifact was novel and the telemetry showed the behavior plainly. That lesson doesn't transfer secondhand.

Enumeration usually works. Most of what hits a mid-size org is commodity, recycled, and already in a feed. The strategy fails specifically against the adversary who matters most and appears least — so the evidence that should update you is exactly the evidence you're least likely to encounter before it's too late.
 