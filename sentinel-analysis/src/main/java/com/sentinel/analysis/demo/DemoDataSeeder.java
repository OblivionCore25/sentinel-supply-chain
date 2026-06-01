package com.sentinel.analysis.demo;

import com.sentinel.analysis.entity.DependencySnapshotEntity;
import com.sentinel.analysis.entity.ProjectEntity;
import com.sentinel.analysis.repository.DependencySnapshotRepository;
import com.sentinel.analysis.repository.ProjectRepository;
import com.sentinel.analysis.service.AnalysisService;
import com.sentinel.common.event.VulnerabilityEvent;
import com.sentinel.common.model.EventSource;
import com.sentinel.common.model.Severity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;

/**
 * Seeds the database with realistic demo data for portfolio demonstrations.
 * <p>
 * Activated by the {@code demo} Spring profile. Creates:
 * <ul>
 *   <li>3 sample projects (2 Maven, 1 NPM) with real-world dependency trees</li>
 *   <li>12 known vulnerabilities from NVD/OSV/GitHub Advisory (realistic CVEs)</li>
 *   <li>Risk scores computed via the real analysis pipeline</li>
 *   <li>Alerts generated from high-risk scores</li>
 * </ul>
 * <p>
 * This seeder drives data through the <strong>actual</strong> {@link AnalysisService}
 * pipeline — no data is fabricated. The risk scores and alerts are computed
 * from real graph traversal and multi-factor scoring.
 */
@Component
@Profile("demo")
public class DemoDataSeeder implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(DemoDataSeeder.class);

    private final ProjectRepository projectRepo;
    private final DependencySnapshotRepository snapshotRepo;
    private final AnalysisService analysisService;

    public DemoDataSeeder(ProjectRepository projectRepo,
                          DependencySnapshotRepository snapshotRepo,
                          AnalysisService analysisService) {
        this.projectRepo = projectRepo;
        this.snapshotRepo = snapshotRepo;
        this.analysisService = analysisService;
    }

    @Override
    public void run(String... args) {
        if (projectRepo.count() > 0) {
            log.info("Demo data already exists ({} projects), skipping seeder.", projectRepo.count());
            return;
        }

        log.info("╔══════════════════════════════════════════╗");
        log.info("║  SENTINEL — Demo Data Seeder             ║");
        log.info("║  Populating sample projects and vulns...  ║");
        log.info("╚══════════════════════════════════════════╝");

        // 1. Create projects and dependency trees
        UUID paymentApi = createPaymentApiProject();
        UUID webPortal = createWebPortalProject();
        UUID dataService = createDataServiceProject();

        log.info("Created 3 demo projects: payment-api, web-portal, data-service");

        // 2. Simulate vulnerability disclosures through the real pipeline
        seedVulnerabilities();

        log.info("╔══════════════════════════════════════════╗");
        log.info("║  Demo seeding complete!                  ║");
        log.info("║  Dashboard: http://localhost:3000         ║");
        log.info("╚══════════════════════════════════════════╝");
    }

    // ---- Project 1: Java Payment API (Maven) ----

    private UUID createPaymentApiProject() {
        ProjectEntity project = new ProjectEntity("payment-api", "MAVEN");
        project.setRepositoryUrl("https://github.com/sentinel-demo/payment-api");
        project = projectRepo.save(project);

        String tree = """
                {
                  "name": "payment-api",
                  "version": "2.3.1",
                  "dependencies": [
                    {
                      "name": "org.springframework.boot:spring-boot-starter-web",
                      "version": "3.2.0",
                      "dependencies": [
                        {
                          "name": "org.springframework:spring-web",
                          "version": "6.1.1",
                          "dependencies": [
                            {
                              "name": "org.springframework:spring-core",
                              "version": "6.1.1",
                              "dependencies": []
                            }
                          ]
                        },
                        {
                          "name": "com.fasterxml.jackson.core:jackson-databind",
                          "version": "2.15.3",
                          "dependencies": [
                            {
                              "name": "com.fasterxml.jackson.core:jackson-core",
                              "version": "2.15.3",
                              "dependencies": []
                            },
                            {
                              "name": "com.fasterxml.jackson.core:jackson-annotations",
                              "version": "2.15.3",
                              "dependencies": []
                            }
                          ]
                        }
                      ]
                    },
                    {
                      "name": "org.apache.logging.log4j:log4j-core",
                      "version": "2.14.1",
                      "dependencies": [
                        {
                          "name": "org.apache.logging.log4j:log4j-api",
                          "version": "2.14.1",
                          "dependencies": []
                        }
                      ]
                    },
                    {
                      "name": "io.netty:netty-handler",
                      "version": "4.1.86.Final",
                      "dependencies": [
                        {
                          "name": "io.netty:netty-common",
                          "version": "4.1.86.Final",
                          "dependencies": []
                        },
                        {
                          "name": "io.netty:netty-codec",
                          "version": "4.1.86.Final",
                          "dependencies": []
                        }
                      ]
                    },
                    {
                      "name": "com.google.protobuf:protobuf-java",
                      "version": "3.19.4",
                      "dependencies": []
                    },
                    {
                      "name": "org.postgresql:postgresql",
                      "version": "42.5.1",
                      "dependencies": []
                    },
                    {
                      "name": "com.stripe:stripe-java",
                      "version": "22.0.0",
                      "dependencies": [
                        {
                          "name": "com.google.code.gson:gson",
                          "version": "2.10",
                          "dependencies": []
                        }
                      ]
                    }
                  ]
                }
                """;

        snapshotRepo.save(new DependencySnapshotEntity(project.getId(), tree));
        return project.getId();
    }

    // ---- Project 2: React Web Portal (NPM) ----

    private UUID createWebPortalProject() {
        ProjectEntity project = new ProjectEntity("web-portal", "NPM");
        project.setRepositoryUrl("https://github.com/sentinel-demo/web-portal");
        project = projectRepo.save(project);

        String tree = """
                {
                  "name": "web-portal",
                  "version": "1.8.0",
                  "dependencies": [
                    {
                      "name": "react",
                      "version": "18.2.0",
                      "dependencies": [
                        {
                          "name": "loose-envify",
                          "version": "1.4.0",
                          "dependencies": []
                        }
                      ]
                    },
                    {
                      "name": "next",
                      "version": "13.4.19",
                      "dependencies": [
                        {
                          "name": "postcss",
                          "version": "8.4.14",
                          "dependencies": [
                            {
                              "name": "nanoid",
                              "version": "3.3.4",
                              "dependencies": []
                            }
                          ]
                        },
                        {
                          "name": "styled-jsx",
                          "version": "5.1.1",
                          "dependencies": []
                        }
                      ]
                    },
                    {
                      "name": "axios",
                      "version": "1.4.0",
                      "dependencies": [
                        {
                          "name": "follow-redirects",
                          "version": "1.15.2",
                          "dependencies": []
                        }
                      ]
                    },
                    {
                      "name": "jsonwebtoken",
                      "version": "8.5.1",
                      "dependencies": [
                        {
                          "name": "jws",
                          "version": "3.2.2",
                          "dependencies": []
                        },
                        {
                          "name": "lodash",
                          "version": "4.17.21",
                          "dependencies": []
                        }
                      ]
                    },
                    {
                      "name": "semver",
                      "version": "7.5.3",
                      "dependencies": []
                    },
                    {
                      "name": "tough-cookie",
                      "version": "4.1.2",
                      "dependencies": [
                        {
                          "name": "psl",
                          "version": "1.9.0",
                          "dependencies": []
                        }
                      ]
                    }
                  ]
                }
                """;

        snapshotRepo.save(new DependencySnapshotEntity(project.getId(), tree));
        return project.getId();
    }

    // ---- Project 3: Python-style Data Service (Maven, simulating polyglot) ----

    private UUID createDataServiceProject() {
        ProjectEntity project = new ProjectEntity("data-service", "MAVEN");
        project.setRepositoryUrl("https://github.com/sentinel-demo/data-service");
        project = projectRepo.save(project);

        String tree = """
                {
                  "name": "data-service",
                  "version": "0.9.5",
                  "dependencies": [
                    {
                      "name": "org.springframework.boot:spring-boot-starter-data-jpa",
                      "version": "3.1.5",
                      "dependencies": [
                        {
                          "name": "org.hibernate.orm:hibernate-core",
                          "version": "6.2.13.Final",
                          "dependencies": [
                            {
                              "name": "org.jboss.logging:jboss-logging",
                              "version": "3.5.3.Final",
                              "dependencies": []
                            }
                          ]
                        }
                      ]
                    },
                    {
                      "name": "org.apache.commons:commons-text",
                      "version": "1.9",
                      "dependencies": [
                        {
                          "name": "org.apache.commons:commons-lang3",
                          "version": "3.12.0",
                          "dependencies": []
                        }
                      ]
                    },
                    {
                      "name": "org.yaml:snakeyaml",
                      "version": "1.33",
                      "dependencies": []
                    },
                    {
                      "name": "com.h2database:h2",
                      "version": "2.1.214",
                      "dependencies": []
                    },
                    {
                      "name": "com.fasterxml.jackson.core:jackson-databind",
                      "version": "2.15.3",
                      "dependencies": [
                        {
                          "name": "com.fasterxml.jackson.core:jackson-core",
                          "version": "2.15.3",
                          "dependencies": []
                        }
                      ]
                    },
                    {
                      "name": "org.apache.logging.log4j:log4j-core",
                      "version": "2.14.1",
                      "dependencies": [
                        {
                          "name": "org.apache.logging.log4j:log4j-api",
                          "version": "2.14.1",
                          "dependencies": []
                        }
                      ]
                    }
                  ]
                }
                """;

        snapshotRepo.save(new DependencySnapshotEntity(project.getId(), tree));
        return project.getId();
    }

    // ---- Vulnerability Events ----

    /**
     * Feeds realistic vulnerability events through the actual AnalysisService pipeline.
     * Each event triggers: upsert → graph build → scoring → alert generation.
     */
    private void seedVulnerabilities() {
        Instant now = Instant.now();
        List<VulnerabilityEvent> events = List.of(
                // === CRITICAL ===
                new VulnerabilityEvent(
                        "CVE-2021-44228",
                        "org.apache.logging.log4j:log4j-core",
                        ">=2.0.0, <2.17.1",
                        10.0, Severity.CRITICAL,
                        "Apache Log4j2 JNDI features do not protect against attacker-controlled LDAP and other JNDI endpoints. " +
                                "An attacker who can control log messages or log message parameters can execute arbitrary code.",
                        EventSource.NVD,
                        Instant.parse("2021-12-10T02:36:00Z"),
                        now
                ),
                new VulnerabilityEvent(
                        "CVE-2022-42889",
                        "org.apache.commons:commons-text",
                        ">=1.5, <1.10.0",
                        9.8, Severity.CRITICAL,
                        "Apache Commons Text StringSubstitutor performs variable interpolation, allowing properties to be " +
                                "looked up and evaluated. This can lead to remote code execution (Text4Shell).",
                        EventSource.NVD,
                        Instant.parse("2022-10-13T13:15:00Z"),
                        now
                ),
                new VulnerabilityEvent(
                        "CVE-2023-44487",
                        "io.netty:netty-codec",
                        "<4.1.100.Final",
                        9.1, Severity.CRITICAL,
                        "HTTP/2 Rapid Reset Attack allows DoS by sending a large number of RST_STREAM frames. " +
                                "This affects Netty's HTTP/2 codec implementation.",
                        EventSource.NVD,
                        Instant.parse("2023-10-10T14:15:00Z"),
                        now
                ),

                // === HIGH ===
                new VulnerabilityEvent(
                        "CVE-2023-34034",
                        "org.springframework:spring-web",
                        ">=6.0.0, <6.0.11",
                        8.8, Severity.HIGH,
                        "Spring Framework authorization bypass in URL pattern matching. " +
                                "Applications using patterns with ** on a segment may be vulnerable to authorization bypass.",
                        EventSource.GITHUB,
                        Instant.parse("2023-07-17T09:15:00Z"),
                        now
                ),
                new VulnerabilityEvent(
                        "CVE-2022-31692",
                        "com.fasterxml.jackson.core:jackson-databind",
                        ">=2.13.0, <2.13.5",
                        8.1, Severity.HIGH,
                        "Deserialization of untrusted data when using JsonTypeInfo.Id.CLASS or MINIMAL_CLASS " +
                                "can lead to remote code execution.",
                        EventSource.NVD,
                        Instant.parse("2022-11-21T12:15:00Z"),
                        now
                ),
                new VulnerabilityEvent(
                        "GHSA-qwcr-r2fm-qrc7",
                        "next",
                        ">=13.0.0, <13.5.1",
                        8.0, Severity.HIGH,
                        "Next.js Server-Side Request Forgery (SSRF) vulnerability. The Next.js image optimization " +
                                "component allows Server-Side Request Forgery in certain configurations.",
                        EventSource.GITHUB,
                        Instant.parse("2023-09-19T15:00:00Z"),
                        now
                ),
                new VulnerabilityEvent(
                        "CVE-2023-24807",
                        "tough-cookie",
                        "<4.1.3",
                        7.5, Severity.HIGH,
                        "Prototype pollution in tough-cookie via Set-Cookie header parsing. " +
                                "An attacker can alter Object.prototype via crafted cookie values.",
                        EventSource.OSV,
                        Instant.parse("2023-02-15T10:00:00Z"),
                        now
                ),

                // === MEDIUM ===
                new VulnerabilityEvent(
                        "CVE-2022-25883",
                        "semver",
                        ">=7.0.0, <7.5.4",
                        6.5, Severity.MEDIUM,
                        "Regular expression denial of service (ReDoS) in semver versions " +
                                "prior to 7.5.4 due to a bad regex in the SemVer comparison logic.",
                        EventSource.OSV,
                        Instant.parse("2023-06-21T09:15:00Z"),
                        now
                ),
                new VulnerabilityEvent(
                        "CVE-2023-26159",
                        "follow-redirects",
                        "<1.15.4",
                        6.1, Severity.MEDIUM,
                        "Improper input validation in follow-redirects allows URL redirection to untrusted sites " +
                                "when using proxy configurations.",
                        EventSource.GITHUB,
                        Instant.parse("2024-01-02T05:15:00Z"),
                        now
                ),
                new VulnerabilityEvent(
                        "CVE-2022-38750",
                        "org.yaml:snakeyaml",
                        "<1.32",
                        5.5, Severity.MEDIUM,
                        "SnakeYAML allows stack overflow via crafted YAML files due to recursive constructors. " +
                                "Denial of service via unchecked recursion depth.",
                        EventSource.NVD,
                        Instant.parse("2022-09-05T08:15:00Z"),
                        now
                ),
                new VulnerabilityEvent(
                        "CVE-2022-41854",
                        "org.yaml:snakeyaml",
                        "<1.32",
                        5.3, Severity.MEDIUM,
                        "SnakeYAML uncontrolled resource consumption via crafted YAML input. " +
                                "Integer overflow in bitwise shift operation during parsing.",
                        EventSource.OSV,
                        Instant.parse("2022-11-11T12:15:00Z"),
                        now
                ),

                // === LOW ===
                new VulnerabilityEvent(
                        "CVE-2021-23337",
                        "lodash",
                        "<4.17.21",
                        3.3, Severity.LOW,
                        "Prototype pollution in lodash template function. " +
                                "An attacker can modify Object prototype properties via template injection.",
                        EventSource.OSV,
                        Instant.parse("2021-02-15T11:15:00Z"),
                        now
                )
        );

        for (int i = 0; i < events.size(); i++) {
            VulnerabilityEvent event = events.get(i);
            log.info("Processing vulnerability [{}/{}]: {} ({})",
                    i + 1, events.size(), event.cveId(), event.severity());
            try {
                analysisService.processVulnerability(event);
            } catch (Exception e) {
                log.warn("Failed to process {}: {}", event.cveId(), e.getMessage());
            }
        }

        log.info("Seeded {} vulnerability events through the analysis pipeline", events.size());
    }
}
