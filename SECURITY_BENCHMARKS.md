# Security-Focused Benchmarks: A Curated Reference

A categorized list of benchmarks, datasets, and test suites used to evaluate security
tools, machine-learning models, LLMs/agents, and security products. Entries note the
approximate year of introduction, what the benchmark measures, and a pointer (official
site, repository, or paper) where one can be given confidently.

**Scope note.** "Benchmark" is used broadly here: some entries are curated evaluation
suites with ground truth and scoring harnesses, some are widely reused research datasets,
some are deliberately vulnerable systems used as test beds, and some are configuration
or product-testing standards that carry the name "benchmark" in industry.

## Contents

1. [Static / dynamic analysis tool benchmarks (SAST, DAST, crypto misuse)](#1-static--dynamic-analysis-tool-benchmarks)
2. [Vulnerability-detection datasets (ML / LLM)](#2-vulnerability-detection-datasets-ml--llm)
3. [Vulnerability repair and patching benchmarks](#3-vulnerability-repair-and-patching-benchmarks)
4. [Secure code generation benchmarks (LLMs)](#4-secure-code-generation-benchmarks-llms)
5. [LLM cybersecurity knowledge and reasoning benchmarks](#5-llm-cybersecurity-knowledge-and-reasoning-benchmarks)
6. [Offensive-security, CTF, and autonomous-agent benchmarks](#6-offensive-security-ctf-and-autonomous-agent-benchmarks)
7. [LLM and agent attack-robustness benchmarks](#7-llm-and-agent-attack-robustness-benchmarks)
8. [Fuzzing and bug-finding benchmarks](#8-fuzzing-and-bug-finding-benchmarks)
9. [Deliberately vulnerable applications and wargames](#9-deliberately-vulnerable-applications-and-wargames)
10. [Network intrusion detection datasets](#10-network-intrusion-detection-datasets)
11. [Malware and software supply chain datasets](#11-malware-and-software-supply-chain-datasets)
12. [Phishing, spam, and social engineering datasets](#12-phishing-spam-and-social-engineering-datasets)
13. [Smart contract and blockchain security benchmarks](#13-smart-contract-and-blockchain-security-benchmarks)
14. [Android and mobile security benchmarks](#14-android-and-mobile-security-benchmarks)
15. [Hardware and side-channel security benchmarks](#15-hardware-and-side-channel-security-benchmarks)
16. [ML robustness, backdoor, and model-security benchmarks](#16-ml-robustness-backdoor-and-model-security-benchmarks)
17. [Configuration hardening baselines](#17-configuration-hardening-baselines)
18. [Industry product-testing benchmarks](#18-industry-product-testing-benchmarks)
19. [Underlying corpora, feeds, and indexes](#19-underlying-corpora-feeds-and-indexes)
20. [Caveats when using these benchmarks](#20-caveats-when-using-these-benchmarks)

---

## 1. Static / dynamic analysis tool benchmarks

Ground-truth test suites for scoring static analyzers (SAST), dynamic scanners (DAST),
and related tooling on true/false positive rates.

| Benchmark | Year | Focus | Pointer |
|---|---|---|---|
| NIST SARD (Software Assurance Reference Dataset) | 2006– | 100k+ CWE-labeled test programs in C/C++, Java, PHP, C# with known weaknesses | https://samate.nist.gov/SARD/ |
| Juliet Test Suites (part of SARD) | 2010– | Synthetic CWE-labeled cases: ~64k C/C++ and ~29k Java tests (v1.3) | https://samate.nist.gov/SARD/ |
| NIST SATE (Static Analysis Tool Exposition) | 2008–2018 | Recurring tool exposition using synthetic and CVE-based production targets | NIST SAMATE program |
| OWASP Benchmark | 2015– | 2,740 exploitable Java web test cases; scores SAST/DAST/IAST tools on TPR vs. FPR | https://owasp.org/www-project-benchmark/ |
| Securibench / Securibench Micro | 2005–06 | Early Stanford suites of Java web apps and micro-tests for taint analysis | Livshits & Lam, Usenix Security 2005 |
| Toyota ITC benchmark | 2015 | ~1,300 C functions in with/without-defect pairs across ~50 defect types (automotive) | https://github.com/regehr/itc-benchmarks |
| OpenSSF CVE Benchmark | 2020 | 200+ real JavaScript/TypeScript CVEs with pre-/post-fix code for scoring code scanners | https://github.com/ossf-cve-benchmark/ossf-cve-benchmark |
| WAVSEP | 2010– | Web Application Vulnerability Scanner Evaluation Project: SQLi/XSS/LFI/RFI test cases for DAST scanners | https://github.com/sectooladdict/wavsep |
| WackoPicko | 2010 | Deliberately vulnerable web app built specifically for scanner evaluation studies | Doupé et al., DIMVA 2010 |
| CryptoAPI-Bench | 2019 | ~180 Java test cases of cryptographic API misuse for crypto-misuse detectors | Afrose et al., IEEE SecDev 2019 |
| BugBox | 2013 | Corpus and framework of reproducible PHP web vulnerabilities | Nilson et al., USENIX CSET 2013 |

## 2. Vulnerability-detection datasets (ML / LLM)

Function- or file-level datasets of real (or weakly labeled) vulnerable code, used to
train and evaluate learned vulnerability detectors.

| Dataset | Year | Focus | Pointer |
|---|---|---|---|
| VulDeePecker dataset | 2018 | "Code gadget" slices for CWE-119/CWE-399 drawn from NVD and SARD | Li et al., NDSS 2018 |
| Draper VDISC | 2018 | 1.27M C/C++ functions with weak labels from three static analyzers | Russell et al., ICMLA 2018 |
| Devign | 2019 | Manually labeled vulnerable/non-vulnerable functions from FFmpeg and QEMU | Zhou et al., NeurIPS 2019 |
| CodeXGLUE defect detection | 2021 | Devign packaged as a standard ML benchmark task | https://github.com/microsoft/CodeXGLUE |
| ReVeal | 2021 | Chromium/Debian functions with realistic class imbalance; critiques earlier datasets | https://github.com/VulDetProject/ReVeal |
| Big-Vul | 2020 | 3,754 CVEs mined from CVE-linked commits; ~11k vulnerable C/C++ functions, 91 CWE types | https://github.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset |
| D2A | 2021 | Differential static-analysis labels over OpenSSL, FFmpeg, httpd, nginx, libtiff, libav | https://github.com/IBM/D2A |
| CrossVul | 2021 | Vulnerable/fixed file pairs from CVE patches across 40+ programming languages | Nikitopoulos et al., ESEC/FSE 2021 |
| CVEfixes | 2021 | Auto-collected CVE→fix-commit dataset (5,365 CVEs at release; periodically updated) | https://github.com/secureIT-project/CVEfixes |
| DiverseVul | 2023 | 18,945 vulnerable C/C++ functions across 150 CWEs from 797 projects | https://github.com/wagner-group/diversevul |
| PrimeVul | 2024 | ~7k vulnerable / ~229k benign functions with de-duplication, label verification, and paired evaluation | Ding et al., 2024 ("How Far Are We?") |
| MegaVul | 2024 | 17k+ CVE-linked vulnerable C/C++ functions (later extended to Java); continuously updated | Ni et al., MSR 2024 |
| VulBench | 2023 | Aggregation of CTF and real-world vulnerable code for benchmarking LLM-based detection | Gao et al., 2023 |

## 3. Vulnerability repair and patching benchmarks

Reproducible real vulnerabilities with proof-of-vulnerability tests, used to evaluate
automated program repair and, increasingly, LLM agents.

| Benchmark | Year | Focus | Pointer |
|---|---|---|---|
| ExtractFix dataset | 2021 | ~30 real C/C++ CVEs (libtiff, libxml2, etc.); a de facto standard in vulnerability-repair papers | Gao et al., TOSEM 2021 |
| Vul4J | 2022 | 79 reproducible real Java vulnerabilities (25 CWEs) with PoV test cases | https://github.com/tuhh-softsec/vul4j |
| VJBench | 2023 | 42 additional reproducible Java vulnerabilities extending Vul4J for LLM/APR evaluation | Wu et al., ISSTA 2023 (llm-vul) |
| SecBench.js | 2023 | 600 real, exploitable vulnerabilities in npm/JavaScript packages | Bhuiyan et al., ICSE 2023 |
| ARVO | 2024 | 5,000+ reproducible memory-safety vulnerabilities from OSS-Fuzz projects, with patches | Mei et al., 2024 |
| AutoPatchBench (CyberSecEval 4) | 2025 | LLM repair of fuzzing-found C/C++ crashes, built on ARVO-style reproduction | https://github.com/meta-llama/PurpleLlama |
| CyberGym | 2025 | ~1,500 tasks reproducing real OSS-Fuzz vulnerabilities (PoC generation) for AI agents | Wang et al., 2025 (UC Berkeley) |
| SEC-bench | 2025 | Agent benchmark built from real CVE/OSS-Fuzz artifacts: PoC creation and vulnerability patching | 2025 preprint |

## 4. Secure code generation benchmarks (LLMs)

Do code models emit vulnerable code, and can they be steered not to?

| Benchmark | Year | Focus | Pointer |
|---|---|---|---|
| "Asleep at the Keyboard" scenarios | 2022 | 89 CWE-based scenarios; 1,689 Copilot completions, ~40% vulnerable | Pearce et al., IEEE S&P 2022 |
| SecurityEval | 2022 | ~130 Python prompts covering 75 CWEs for evaluating generated-code security | https://github.com/s2e-lab/SecurityEval |
| LLMSecEval | 2023 | 150 natural-language prompts derived from the CWE Top 25 | Tony et al., MSR 2023 |
| SVEN scenario suite | 2023 | Security-sensitive completion scenarios used to evaluate controlled (secure/insecure) generation | https://github.com/eth-sri/sven |
| CodeLMSec | 2024 | Automatically generated prompts that elicit vulnerable completions from code LLMs | Hajipour et al., IEEE SaTML 2024 |
| SALLM | 2024 | ~100 security-centric Python prompts plus automated functional and security testing | Siddiq et al., 2024 |
| CyberSecEval insecure-code tests | 2023– | Autocomplete and instruct tests for insecure coding practices across languages | https://github.com/meta-llama/PurpleLlama |
| SecCodePLT | 2024 | Unified platform pairing CWE-based secure-codegen tasks (with dynamic tests) and attack-helpfulness tasks | Yang et al., 2024 |
| CWEval | 2025 | Outcome-driven evaluation scoring functionality and security of generated code together | 2025 preprint |

## 5. LLM cybersecurity knowledge and reasoning benchmarks

Question-answering and multi-task suites probing what models know about security.

| Benchmark | Year | Focus | Pointer |
|---|---|---|---|
| MMLU "computer security" subset | 2021 | Security-subject MCQs inside the general MMLU benchmark | Hendrycks et al., ICLR 2021 |
| SecQA | 2023 | MCQs generated from a computer-security textbook (two difficulty tiers) | Liu, 2023 |
| SecEval | 2023 | ~2,100 MCQs across nine security domains (systems, web, crypto, etc.) | Li et al., 2023 |
| CyberMetric | 2024 | RAG-generated, expert-validated cybersecurity MCQs (80/500/2k/10k variants) | Tihanyi et al., 2024 |
| CyberBench | 2024 | Multi-task cyber NLP suite (NER, summarization, classification, QA) for LLMs | Liu et al., 2024 |
| CTIBench | 2024 | Cyber-threat-intelligence tasks: knowledge MCQs, root-cause mapping to CWE, ATT&CK technique mapping, CVSS scoring | Alam et al., NeurIPS 2024 |
| SEvenLLM-Bench | 2024 | Bilingual (en/zh) cybersecurity incident understanding and analysis tasks | Ji et al., 2024 |
| CS-Eval | 2024 | Bilingual multi-category cybersecurity knowledge and reasoning suite | 2024 preprint |
| WMDP-Cyber | 2024 | ≈2,000 MCQs proxying hazardous offensive-cyber knowledge; standard target for unlearning methods | https://www.wmdp.ai |

## 6. Offensive-security, CTF, and autonomous-agent benchmarks

End-to-end challenges measuring whether models/agents can find, exploit, or leverage
vulnerabilities — the core of frontier "cyber capability" evaluations.

| Benchmark | Year | Focus | Pointer |
|---|---|---|---|
| InterCode-CTF | 2023 | 100 picoCTF tasks in a containerized interactive-coding environment | https://github.com/princeton-nlp/intercode |
| NYU CTF Bench | 2024 | 200 dockerized CSAW CTF challenges across six categories for LLM agents | https://github.com/NYU-LLM-CTF |
| Cybench | 2024 | 40 professional CTF tasks with subtasks and first-solve-time difficulty metadata | https://cybench.github.io |
| CyberSecEval 2 exploitation suite | 2024 | Program-exploitation and vulnerability-identification challenges (plus interpreter-abuse tests) | https://github.com/meta-llama/PurpleLlama |
| CyberSecEval 3 offensive suites | 2024 | Spear-phishing persuasion and autonomous/assisted offensive cyber-operation evaluations | https://github.com/meta-llama/PurpleLlama |
| 3CB (Catastrophic Cyber Capabilities Benchmark) | 2024 | Realistic professional-level offensive challenges for autonomous agents | Anurin et al., 2024 |
| AutoPenBench | 2024 | 33 milestone-annotated penetration-testing tasks (synthetic through real CVEs) | Gioacchini et al., 2024 |
| CVE-Bench (web exploitation) | 2025 | ~40 real, critical-severity web CVEs in containers; agents must produce working exploits | Zhu et al., 2025 (UIUC) |
| BountyBench | 2025 | Real bug-bounty systems and dollar-valued Detect / Exploit / Patch tasks | Zhang et al., 2025 (Stanford) |
| DARPA AIxCC challenge projects | 2024–25 | Competition corpus of real OSS with seeded vulnerabilities for automated find-and-fix systems | https://aicyberchallenge.com |
| picoCTF / CSAW / HTB task sets | ongoing | Competition problem sets widely repurposed as agent evaluations (see entries above) | respective platforms |

## 7. LLM and agent attack-robustness benchmarks

Security *of* AI systems: prompt injection, jailbreaks, and harmful-use refusal.

| Benchmark | Year | Focus | Pointer |
|---|---|---|---|
| AdvBench | 2023 | 520 harmful behaviors/strings; basis of the GCG adversarial-suffix attack evaluations | Zou et al., 2023 |
| CyberSecEval prompt-injection suite | 2024 | Direct and indirect textual prompt-injection test cases | https://github.com/meta-llama/PurpleLlama |
| BIPIA | 2023 | Benchmark for indirect prompt injection via poisoned retrieved/external content | https://github.com/microsoft/BIPIA |
| InjecAgent | 2024 | ~1,000 indirect prompt-injection cases against tool-using agents | Zhan et al., ACL Findings 2024 |
| AgentDojo | 2024 | 97 realistic agent tasks + 629 injection security cases in a dynamic environment | https://github.com/ethz-spylab/agentdojo |
| HarmBench | 2024 | 510 harmful behaviors (incl. cybercrime/malware) with automated red-team evaluation | https://github.com/centerforaisafety/HarmBench |
| JailbreakBench | 2024 | 100-behavior open leaderboard for jailbreak attacks and defenses | https://jailbreakbench.github.io |
| StrongREJECT | 2024 | ~300 forbidden prompts with a calibrated grader for jailbreak-success claims | Souly et al., 2024 |
| AgentHarm | 2024 | 110 malicious multi-step agent tasks (440 augmented) across 11 harm categories | Andriushchenko et al., 2024 |
| RedCode | 2024 | Risky code *execution* (RedCode-Exec) and malware-generation (RedCode-Gen) tests for code agents | Guo et al., NeurIPS 2024 |

## 8. Fuzzing and bug-finding benchmarks

Standardized targets with known or injected bugs for comparing fuzzers and
bug-finding/exploitation systems.

| Benchmark | Year | Focus | Pointer |
|---|---|---|---|
| LAVA-M | 2016 | Four coreutils programs with thousands of automatically injected bugs | https://github.com/panda-re/lava |
| DARPA CGC corpus | 2016 | 200+ purpose-built challenge binaries from the Cyber Grand Challenge; standard for AEG research | https://github.com/trailofbits/cb-multios |
| Magma | 2020 | Nine real libraries with 100+ forward-ported real bugs instrumented as canaries | https://hexhive.epfl.ch/magma/ |
| FuzzBench | 2020 | Google's free service benchmarking fuzzers on OSS-Fuzz targets (coverage and bug metrics) | https://github.com/google/fuzzbench |
| UniBench | 2021 | 20 real-world programs across six categories for holistic fuzzer comparison | https://github.com/unifuzz/unibench |
| ProFuzzBench | 2021 | Stateful network-protocol servers (FTP, SMTP, TLS, …) for protocol fuzzers | https://github.com/profuzzbench/profuzzbench |
| Rode0day | 2018– | Recurring bug-finding competition with LAVA-style injected-bug corpora | https://rode0day.mit.edu |
| OSS-Fuzz (infrastructure) | 2016– | Not itself a benchmark, but the substrate for FuzzBench, ARVO, AutoPatchBench, and CyberGym | https://github.com/google/oss-fuzz |

## 9. Deliberately vulnerable applications and wargames

Purpose-built insecure systems used as test beds for scanners, training, and
increasingly as LLM-agent evaluation targets.

| Target | Domain | Notes | Pointer |
|---|---|---|---|
| OWASP WebGoat | Java web | Lesson-structured insecure web app | https://owasp.org/www-project-webgoat/ |
| OWASP Juice Shop | Node.js web | Modern insecure web shop with scoring/CTF mode | https://owasp.org/www-project-juice-shop/ |
| DVWA | PHP web | Damn Vulnerable Web Application; difficulty tiers per vuln class | https://github.com/digininja/DVWA |
| bWAPP / Mutillidae II | PHP web | Large catalogs of web vulnerability exercises | project sites |
| NodeGoat / RailsGoat | Node / Rails | OWASP Top-10 demonstrations per framework | OWASP projects |
| AltoroJ (Altoro Mutual) | Java web | Classic insecure banking demo app used in scanner marketing/evals | IBM/HCL AppScan demo |
| OWASP crAPI | API | "Completely ridiculous API" for API-security testing | https://github.com/OWASP/crAPI |
| VAmPI | API | Vulnerable REST API (OWASP API Top 10) | community project |
| DVGA | GraphQL | Damn Vulnerable GraphQL Application | community project |
| Metasploitable 2/3 | Full VM | Intentionally vulnerable virtual machines for network/pentest practice | Rapid7 |
| VulnHub | Full VM | Community library of boot-to-root vulnerable images | https://www.vulnhub.com |
| OverTheWire / pwn wargames | Systems | Classic privilege-escalation and binary wargames | https://overthewire.org |
| Hack The Box / PentesterLab | Platform | Commercial labs; retired HTB machines feed research benchmarks (e.g., Cybench) | platform sites |

## 10. Network intrusion detection datasets

Traffic corpora with labeled attacks for evaluating IDS/anomaly detection.

| Dataset | Year | Focus | Pointer |
|---|---|---|---|
| DARPA 1998/1999 (MIT Lincoln Lab) | 1998–99 | First standard IDS corpora; foundational but heavily critiqued | MIT Lincoln Laboratory |
| KDD Cup 1999 | 1999 | Feature-vector derivative of DARPA98; historic staple with known redundancy issues | UCI KDD archive |
| NSL-KDD | 2009 | Cleaned, de-duplicated revision of KDD'99 | https://www.unb.ca/cic/datasets/ |
| Kyoto 2006+ | 2009 | Long-running honeypot traffic dataset | Kyoto University |
| CTU-13 | 2011 | Thirteen labeled botnet traffic scenarios | https://www.stratosphereips.org |
| ISCX-IDS 2012 | 2012 | Profile-generated realistic traffic with attacks | https://www.unb.ca/cic/datasets/ |
| UNSW-NB15 | 2015 | Hybrid realistic/synthetic traffic, nine attack categories | UNSW Canberra |
| CICIDS2017 / CSE-CIC-IDS2018 | 2017–18 | Widely used modern IDS benchmarks (brute force, DoS, botnet, infiltration, web) | https://www.unb.ca/cic/datasets/ |
| CIC-DDoS2019, CIC-IoT2023, CICMalDroid, ISCX-URL2016 | 2016–2023 | The broader CIC family: DDoS, IoT, Android malware, malicious URLs | https://www.unb.ca/cic/datasets/ |
| Bot-IoT / TON_IoT | 2018–20 | IoT/IIoT telemetry + network datasets with labeled attacks | UNSW Canberra |
| MAWILab | 2010– | Automatically labeled anomalies in real backbone traffic (MAWI archive) | Fukuda Lab |
| UGR'16 | 2016 | Months of real NetFlow with injected/labeled attacks | University of Granada |

## 11. Malware and software supply chain datasets

| Dataset | Year | Focus | Pointer |
|---|---|---|---|
| EMBER | 2018 | 1.1M Windows PE feature vectors for static malware detection (later refreshes exist) | https://github.com/elastic/ember |
| SOREL-20M | 2020 | ~20M PE samples with features; ~10M disarmed malware binaries | Sophos + ReversingLabs |
| BODMAS | 2021 | 57,293 malware / 77,142 benign PE files, timestamped, with family labels | Yang et al., 2021 |
| MOTIF | 2022 | 3,095 disarmed samples across 454 families, ground truth from CTI reports | https://github.com/boozallen/MOTIF |
| Microsoft Malware Classification (BIG 2015) | 2015 | ~20k samples across nine families; classic Kaggle classification benchmark | https://www.kaggle.com/c/malware-classification |
| Malimg | 2011 | 9,339 malware grayscale images, 25 families (visualization-based classification) | Nataraj et al., 2011 |
| Drebin | 2014 | 5,560 Android malware apps, 179 families; canonical Android ML dataset | TU Braunschweig |
| AndroZoo | 2016– | 20M+ Android APKs with VirusTotal metadata (research corpus) | https://androzoo.uni.lu |
| CIC-AndMal2017 / CICMalDroid2020 | 2017–20 | Android malware with static and dynamic features | https://www.unb.ca/cic/datasets/ |
| Backstabber's Knife Collection | 2020 | Curated corpus of real malicious npm/PyPI/RubyGems packages (supply chain) | Ohm et al., DIMVA 2020 |
| VirusShare / VX Underground / MalwareBazaar | ongoing | Raw sample corpora and feeds underlying many derived datasets | respective sites |

## 12. Phishing, spam, and social engineering datasets

| Dataset | Year | Focus | Pointer |
|---|---|---|---|
| PhishTank / OpenPhish | ongoing | Community/commercial verified phishing URL feeds; standard positive sources | https://phishtank.org |
| Nazario phishing corpus | 2004– | Long-running collection of phishing emails | Jose Nazario |
| UCI Phishing Websites | 2015 | 11,055 instances / 30 hand-crafted features; ubiquitous (use with caveats) | UCI ML Repository |
| ISCX-URL2016 | 2016 | Benign vs. spam/phishing/malware/defacement URLs | https://www.unb.ca/cic/datasets/ |
| SpamAssassin / Enron / TREC spam corpora | 2002–07 | Canonical email corpora for spam filtering research | respective archives |
| CyberSecEval 3 spear-phishing eval | 2024 | LLM persuasion-based phishing simulation (model-vs-model) | https://github.com/meta-llama/PurpleLlama |

## 13. Smart contract and blockchain security benchmarks

| Benchmark | Year | Focus | Pointer |
|---|---|---|---|
| SmartBugs + SB-Curated | 2020 | Execution framework plus 143 annotated vulnerable Solidity contracts (10 DASP categories) | https://github.com/smartbugs/smartbugs |
| SmartBugs-Wild | 2020 | 47,398 real-world contracts for large-scale tool comparison | https://github.com/smartbugs |
| SolidiFI | 2020 | Thousands of bugs injected into 50 contracts across seven types; evaluates analyzer recall | Ghaleb & Pattabiraman, ISSTA 2020 |
| Not So Smart Contracts | 2018 | Curated examples of real Solidity vulnerability patterns | https://github.com/crytic/not-so-smart-contracts |
| SWC Registry | 2018 | Smart-contract weakness classification with test cases (now archived; still cited) | https://swcregistry.io |
| DAppSCAN | 2023 | SWC-annotated contracts mined from professional audit reports | Zheng et al., 2023 |
| Ethernaut | 2017– | OpenZeppelin's Solidity wargame; reused as an LLM-agent benchmark | https://ethernaut.openzeppelin.com |
| Damn Vulnerable DeFi | 2020– | Offensive challenges for DeFi/flash-loan logic flaws | https://www.damnvulnerabledefi.xyz |

## 14. Android and mobile security benchmarks

| Benchmark | Year | Focus | Pointer |
|---|---|---|---|
| DroidBench | 2014 | ~120 micro-apps testing taint-analysis precision/recall (FlowDroid et al.) | https://github.com/secure-software-engineering/DroidBench |
| ICC-Bench | 2015 | Inter-component-communication leak benchmarks | Wei et al. |
| Ghera | 2017 | 60+ lean, reproducible benchmarks of known Android app vulnerabilities (benign + exploit apps) | Mitra & Ranganath |
| DIVA Android | 2016 | Damn Insecure and Vulnerable App for hands-on mobile testing | community project |
| OWASP MAS (MASVS/MASTG) + UnCrackable apps | ongoing | Mobile verification standard, testing guide, and crackme benchmark apps | https://mas.owasp.org |
| Drebin / AndroZoo / CIC Android sets | 2014– | Malware-side datasets (see section 11) | see above |

## 15. Hardware and side-channel security benchmarks

| Benchmark | Year | Focus | Pointer |
|---|---|---|---|
| Trust-Hub benchmarks | 2013– | Standard hardware-Trojan-inserted designs and vulnerability benchmarks | https://trust-hub.org |
| Hack@DAC buggy SoCs | 2018– | Competition SoCs (e.g., OpenPiton-based) with seeded security bugs; several released publicly | Hack@Event competitions |
| DPA Contest series | 2008–16 | Standardized side-channel trace sets for attack comparison | DPA Contest organizers |
| ASCAD | 2018 | ANSSI AES side-channel traces; the standard deep-learning SCA benchmark | https://github.com/ANSSI-FR/ASCAD |

## 16. ML robustness, backdoor, and model-security benchmarks

Security of machine-learning models themselves.

| Benchmark | Year | Focus | Pointer |
|---|---|---|---|
| RobustBench | 2020 | Standardized adversarial-robustness leaderboard (AutoAttack on CIFAR/ImageNet) | https://robustbench.github.io |
| AdvGLUE | 2021 | Adversarial robustness benchmark for NLP models on GLUE tasks | Wang et al., NeurIPS 2021 |
| NIST TrojAI | 2019– | Rounds of trojaned-vs-clean models; detect the poisoned ones | https://pages.nist.gov/trojai/ |
| Trojan Detection Challenge | 2022–23 | NeurIPS competition series on detecting/evaluating neural backdoors | competition site |
| BackdoorBench | 2022 | Standardized implementations and evaluation of backdoor attacks/defenses | https://github.com/SCLBD/BackdoorBench |

## 17. Configuration hardening baselines

"Benchmarks" in the compliance sense: consensus secure-configuration standards that
systems are audited against (not datasets).

| Standard | Scope | Pointer |
|---|---|---|
| CIS Benchmarks | 100+ hardening guides: OSes, clouds, Kubernetes, databases, browsers; audited by tools like kube-bench and Docker Bench | https://www.cisecurity.org/cis-benchmarks |
| DISA STIGs | U.S. DoD Security Technical Implementation Guides | https://public.cyber.mil/stigs/ |
| NIST National Checklist Program | Repository of SCAP-expressed configuration checklists | https://ncp.nist.gov |
| SCAP Security Guide / OpenSCAP | Open-source SCAP content implementing CIS/STIG profiles | https://www.open-scap.org |
| Microsoft Security Baselines | Recommended hardened settings for Windows and Microsoft products | Microsoft Security Compliance Toolkit |

## 18. Industry product-testing benchmarks

Independent, recurring evaluations of commercial security products.

| Program | Focus | Pointer |
|---|---|---|
| MITRE ATT&CK Evaluations | EDR/endpoint detection tested against emulated APT tradecraft (APT3, APT29, Carbanak/FIN7, Turla, …) | https://attackevals.mitre.org |
| AV-TEST | Antivirus/endpoint protection, performance, usability scoring | https://www.av-test.org |
| AV-Comparatives | Real-world protection and malware-detection test series | https://www.av-comparatives.org |
| SE Labs | Breach-response and endpoint efficacy ratings | https://selabs.uk |
| NetSecOPEN | Open standards for network-security-device performance testing | https://www.netsecopen.org |

## 19. Underlying corpora, feeds, and indexes

Raw sources that many benchmarks above are built from, plus meta-indexes.

- **NVD / CVE, GitHub Advisory Database, OSV.dev** — vulnerability metadata feeding Big-Vul, CVEfixes, CrossVul, CVE-Bench, etc.
- **Exploit-DB and Metasploit modules** — exploit ground truth used to validate exploitability.
- **OSS-Fuzz issue corpus** — the substrate behind ARVO, AutoPatchBench, CyberGym, FuzzBench.
- **RockYou and related breach corpora** — standard lists for password-cracking and strength-meter benchmarks.
- **CAIDA telescope/DDoS datasets** — backbone and darknet traffic for DoS research.
- **SecRepo.com** — long-running community index of security datasets.

## 20. Caveats when using these benchmarks

- **Label noise is pervasive.** Automatically mined vulnerability datasets (Devign,
  Big-Vul, and kin) have documented label-error rates; PrimeVul and ReVeal both showed
  that reported detector performance collapses under cleaner labeling.
- **Contamination.** Most public benchmarks predate current LLM training cutoffs;
  memorization can inflate scores. Prefer paired/perturbed evaluation (PrimeVul),
  freshly built tasks (CyberGym, BountyBench), or private splits.
- **Synthetic ≠ real.** Juliet/OWASP-Benchmark-style suites measure rule coverage,
  not real-world efficacy; pair them with real-CVE benchmarks (OpenSSF CVE Benchmark,
  Magma) before drawing conclusions about tools.
- **Age matters.** KDD'99-era network data and 2015-vintage phishing features no longer
  reflect deployed attacks; results on them rarely transfer.
- **Dual-use.** Offensive benchmarks (sections 6–7) exist to *measure and mitigate*
  risk; respect the terms and safety guidance their maintainers publish.
