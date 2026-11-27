# CLI 빠른 참조

작업 저장소에서 실행한다. 아래 `graph`는 플러그인의 실제 CLI 경로를 정하는 셸 함수일 뿐이다.

```sh
graph() { node "${CLAUDE_PLUGIN_ROOT:-$PLUGIN_ROOT}/scripts/graph/cli.mjs" "$@"; }
graph host-caps
graph init
graph compile --run survey --spec spec.json --op-id compile-survey
graph ready --run survey
graph claim --run survey --node api --expected-rev 1 --op-id claim-api
```

모든 응답은 JSON 한 줄이다. 성공 시 `result`, 실패 시 `error.code`를 읽는다. 위 `claim`의 `result.instructionPath`를 호스트 전용 `$token`에 둔다. 작업자에게는 읽기 프롬프트와 필요한 논리 입력만 전달한다. 호스트가 실제 작업자를 호출한 다음:

```sh
graph start --token "$token" --host-handle "$actual_handle"
graph settle --token "$token" --op-id settle-api --outcome accepted --receipt worker.json
graph status --run survey
graph metrics --run survey
```

| 명령 | 계약 |
|---|---|
| `init` | 저장소와 상태 경로의 파일시스템을 먼저 검사한다. 필요하면 모든 호출에 같은 `--workspace DIR --root DIR`를 지정한다. |
| `compile` | `--spec FILE`에 버전 1 명세를 전달한다. 노드는 `id`, `kind`, `prompt`, `dependsOn`, 읽기·쓰기 범위와 예상 작업량을 선언한다. `gateArgv`는 호스트가 미리 고정한 명령 인자 배열이다. |
| `ready` | 관찰 전용. `--as-of ISO`는 미리보기 시각이고, `--cursor`에는 직전 응답의 `nextCursor`를 넣는다. |
| `claim` / `start` / `settle` | `claim`은 개정 번호와 작업 ID를 재확인한다. `start`는 실제 호스트 핸들을 연결한다. `settle`에는 워커 영수증을 전달한다. 컴파일된 게이트가 있으면 엔진이 직접 측정한다. 없는 경우 `--gate-log FILE`은 **독립적으로 측정한 호스트 로그**만 받는다. |
| `gate` | `--run ID --node ID --receipt FILE --out FILE`로 이미 고정된 게이트를 별도로 측정한다. Run을 승인하거나 기존 로그를 덮어쓰지 않는다. |
| `status` / `metrics` | 현재 Run 상태와 관측된 계측을 조회한다. `--telemetry FILE`과 `--probe FILE`은 시도 명령에서만 전달하는 호스트 입력이다. 작업자 보고는 사용량·게이트 근거가 아니다. |
| `amend` / `expand` / `inject-repair` | `--run ID --node ID --expected-rev N --op-id OP --patch FILE`. 수정은 `{"exec":{"prompt":"…"}}` 또는 `{"gate":{"timeoutMs":30000}}`; 확장은 `{"shards":[{"stableShardKey":"api"}]}`. 복구는 실패 영수증을 입력으로 하는 새 물리 노드를 만든다. |
| `revalidate` | `--run ID --node ID --expected-rev N --op-id OP`. 증거가 일치할 때만 `NodeRevalidated`를 기록한다. 현재 검증을 생략하는 옵션이 아니다. |
| `reduce` / `retry` / `resume` / `gc` | `reduce`는 필수 명단을 대조한다. `retry`는 예산과 시각이 허용한 인프라 재시도만 연다. `resume`은 저널을 검증하며 `gc`는 루트 전체를 확인한 뒤 고아만 수거한다. |

**영수증:** `workerReportedStatus`, `inlineSummary`, `provenance`를 제출한다. `provenance`에는 `evidenceSpans`, `claims`, `edgeCases`, `failureEvidence` 배열과 그 네 배열에서 엔진의 `factDigest()`로 계산한 값이 필요하다. 파일 스팬의 `path`는 저장소 상대 경로이며 `startLine`과 `endLine`은 양 끝을 포함하는 1부터 시작하는 행 번호다. `claims[].spanIds` 등은 실제 스팬을 가리켜야 한다. 호스트 게이트 로그에는 실제 `argv`, `envDigest`, `exitCode`, `signal`, `subjectDigest`를 기록한다. 워커가 이 값을 써서 자기 작업을 승인할 수 없다.
