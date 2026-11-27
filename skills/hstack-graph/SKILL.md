---
name: hstack-graph
description: 독립된 읽기·검증 작업을 여러 호스트 작업자에게 나누고, 검증된 출처와 누락 없는 증거 색인을 모아야 할 때 사용하는 무데몬 그래프 실행 절차입니다.
---

# hstack:hstack-graph

호스트가 작업자를 실행하고, CLI는 짧은 호출마다 로컬 상태와 증거를 기록한다. CLI가 작업자를 자동 실행하지는 않는다. `node "$PLUGIN_ROOT/scripts/graph/cli.mjs"`를 사용한다. Claude Code에서는 `$PLUGIN_ROOT` 대신 `$CLAUDE_PLUGIN_ROOT`를 사용한다.

1. **입학:** `init`으로 로컬 저장소를 확인한 뒤 `compile`에 명세를 전달한다. `single_session`이면 한 세션에서 순차 처리한다. `dag_approved`인 경우에만 읽기 팬아웃을 사용한다.
2. **배정:** `ready`의 페이지를 읽고 해당 `graphRev`로 `claim`한다. 호스트가 `host-caps`와 실제 권한을 대조한 뒤 Agy `invoke_subagent` 또는 Claude Code `Agent`로 호출한다. 작업자에게는 지정한 프롬프트와 읽기 입력만 준다. 엔진 전용 비밀 지시서는 넘기지 않는다.
3. **실행과 검증:** 디스패치를 확인하면 `start`, 결과가 오면 원래 시도의 토큰과 고정 `opId`로 `settle`한다. 작업자의 보고와 호스트의 측정은 별개다. 이전 epoch의 코드 `49`는 재시도하지 않는다. 보류·논리 실패·flaky 진단을 성공으로 바꾸지 않는다.
4. **축약과 종료:** `reduce`는 봉인된 명단을 기준으로 출처·실패·반증을 선병합한다. 하나라도 빠지거나 역조회되지 않으면 `partial`이다. `ready`가 빈 것만으로 종료하지 말고 `status`에서 필수 작업과 `completed`·`held`·`degraded`를 확인한다. 관측되지 않은 토큰·비용은 `null`이다.

병렬 코드 쓰기와 Git 통합은 v1 기능이 아니다. `ERR_V2_WRITE_INTEGRATION_NOT_ENABLED`를 우회하지 않는다. 락이나 WAL이 불확실하면 수동 삭제로 진행하지 않는다.

- [실행 가능한 읽기 노드 예제](references/example.md) · [CLI 참조](references/cli.md) · [대량 팬인](references/mass.md) · [장애 복구](references/recovery.md)
- [장기 작업자 규약](references/long-worker.md): 최근 10턴 관찰, 12턴 단위 마스킹, 실측 창의 55~65%에서 핀 인계, 검사 시간 제한·결정론적 표본·`ERROR` 색인.
- [실제 호스트 점검](references/live-host.md): 패키지 엄격 검증과 별도로 양 호스트에서 확인하는 디스패치·핸드오프·완료 게이트.
