# .harness/

The one directory `ah` owns in a project. Agents never write here directly;
the guard denies it. `ah` writes here on the user's behalf.

| path                | what                                                                              |
| ------------------- | --------------------------------------------------------------------------------- |
| `memory/bugs/`      | incident records. Every rule in the guard traces to one of these or to the blueprint. |
| `hook_tests/`       | project-specific fixtures, same format as `fixtures/`, picked up by `ah test-hooks`. |
| `metrics.jsonl`     | one line per deny or ask, appended by the guard. Gitignored.                      |

In this repository `.harness/memory/bugs/` is also the seed corpus: what the
nine earlier attempts at this tool taught, each as a record with the file and
line it was learned from.
