# v2 쓰기 통합

`schemaVersion: 2` 명세에서만 쓴다. 버전 1 Run에서 `integrate`·`land`를 부르면 `ERR_V2_WRITE_INTEGRATION_NOT_ENABLED`다. 아래 `graph`는 [CLI 참조](cli.md)의 셸 함수다.

## 쓰기 노드 흐름

```sh
graph claim --run R --node api --expected-rev 3 --op-id claim-api   # 엔진이 잠긴 워크트리를 준비한다
graph start --token "$token" --host-handle "$handle" --op-id start-api
# 작업자는 result.worktreePath 안에서만 편집하고 result.env의 TMPDIR를 쓴다
graph settle --token "$token" --op-id settle-api --outcome accepted --receipt "$receiptPath"   # 성공하면 sealed
graph integrate --run R --op-id int-1      # { "status": "idle" }가 나올 때까지 opId를 바꿔 반복
graph land --run R --op-id land-1
```

`claim` 응답에는 `worktreePath`, `tmpDir`, `env`, `receiptPath`, `baseSha`, `dispatch: { cwd, isolation: "none" }`가 들어 있다. 워크트리가 `ready`가 되기 전의 `start`는 `ERR_NOT_READY`다. 쓰기 노드의 게이트는 `settle`이 아니라 `integrate`의 후보 커밋에서 돈다. 그래서 v2 쓰기 노드는 모두 `gateArgv`가 있어야 한다.

## 호스트 격리 기능은 쓰지 않는다

v2 쓰기에는 Claude의 `isolation: worktree`도, Agy의 branch·share 작업공간도 쓰지 않는다. `baseSha`, 워크트리 수명, 위치는 엔진 소유다. 평범한 하위 작업자를 `cwd = worktreePath`와 지시서의 `env`로 띄우면 된다. 엔진 워크트리의 잠금 사유는 언제나 `hstack:`으로 시작한다. 그런 워크트리를 손으로 풀거나 지우지 않는다.

## 영수증

작업자는 영수증 파일을 직접 쓰지 않는다. 호스트 오케스트레이터가 작업자의 마지막 응답으로 영수증을 만들어 `<root>/runs/<runId>/inbox/` 아래의 `receiptPath`에 둔다. 순서는 임시 파일 `open(wx)` → 쓰기 → `fsync` → `rename` → 디렉터리 `fsync`이고, `settle`은 `rename`이 끝난 뒤에만 부른다. `ERR_CLI_INPUT_FILE`(종료 코드 65)이 오면 같은 `opId`와 같은 본문으로 다시 보낸다. 간격은 100 ms에서 시작해 늘리고 최대 5번까지다. 쓰기 노드에서 기준이 되는 것은 봉인된 커밋의 바이트다. 영수증의 근거 스팬도 봉인된 커밋에서 확인된다.

## release

`graph release --token <펜싱된 시도의 지시서 경로> --op-id OP`. 그 작업자가 끝났다는 걸 호스트가 확인한 뒤에만 부른다. 현재 활성 시도나 보존 중인 봉인 시도는 `ERR_NOT_READY`로 거절된다. 정상적으로 끝난 시도의 워크트리는 엔진이 알아서 반납한다.

## integrate 결과

| 상태 | 이유 | 할 일 |
|---|---|---|
| `accepted` | 후보 게이트 녹색, 게시 완료 | 다음 `integrate`. |
| `held_conflict` | `ERR_MERGE_CONFLICT` | `inject-repair`로 고친다. 수리 노드는 원래 `writeScope`를 물려받는다. |
| `held_integration` | `ERR_INTEGRATION_DIVERGED`, `ERR_REPO_CONFIG_TAMPERED`, `ERR_GIT_MERGE_INPUT`, `ERR_GIT_MERGE_FAILED` | 원인을 조사한다. `refs/hstack/**`를 손으로 덮어쓰지 않는다. |
| `failed_logic` | 후보 게이트 적색 | 실패 영수증의 후보 커밋과 측정값을 본다. |

후보를 측정하는 중에 다시 부르면 `ERR_GATE_IN_PROGRESS`다.

## land

```sh
graph land --run R --op-id land-1                                   # 기본 ff-only
graph land --run R --op-id land-2 --mode branch --branch hstack/R
graph land --run R --op-id land-3 --mode merge
graph land --run R --op-id land-4 --mode patch --out ../R.patch
graph land --run R --op-id land-5 --allow partial,dirty-nonoverlap
```

`ff-only`가 기본이다. 갈라진 HEAD는 충돌이 있으면 `ERR_LAND_CONFLICT`, 없으면 `ERR_LAND_PRECONDITION`이고, 그때는 branch·merge·patch 중에서 고른다. `branch`는 작업 트리를 건드리지 않는다. `merge`는 실행된 게이트가 녹색이어야 병합한다. `patch`는 `--out`이 필요하고, 이미 있는 파일은 덮어쓰지 않는다. `--allow partial`은 `degraded` Run을, `dirty-nonoverlap`은 바뀐 경로와 겹치지 않는 변경을 허용한다.

거절되는 경우는 이렇다. `ERR_LAND_PRECONDITION`은 accepted ref가 기록과 다르거나, Run이 완료되지 않았거나, detached HEAD에서 `--mode branch` 없이 부른 경우다. `ERR_LAND_DIRTY`는 더러운 작업 트리이고, 바뀐 경로와 겹치는 ignored 파일도 여기에 들어간다. `ERR_LAND_CONFLICT`는 병합 미리보기 충돌이다. `ERR_REPO_CONFIG_TAMPERED`는 저장소 설정이 바뀐 경우이고, checkout 전에 검사한다.

## gc

`graph gc --scope git --run R`은 통합이 끝난 pin ref와 지난 세대의 cand ref만 지운다. accepted ref는 남긴다. `--scope` 없이 부르거나 `--scope cas`면 v1 CAS GC다.

## 계획자 절차

1. import 그래프의 클러스터로 나누고 각 `writeScope`는 리터럴 접두어로 쓴다.
2. compile 전에 직접 점검한다. f ≥ 0.65, d < 1.2(엄격 부등호), 추정 총 15분 이상, 독립 노드 3개 이상, `readConcurrency` ≥ 2.
3. 기준을 못 넘으면 최대 두 번 다시 나눈다. 그때마다 새 runId `<base>-p<k>`를 쓴다.
4. 그래도 안 되면 한 세션에서 순차 처리한다.
