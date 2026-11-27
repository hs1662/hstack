# 대량 읽기 프리셋

`compile --run survey --spec mass.json`에 다음 형식의 명세를 준다. `shards`에 읽기 대상마다 영속적인 ID를 부여한다. 아래 예제는 명단 형식을 보이는 축소 예다. 작은 명세에는 단일 세션이 권고될 수 있다.

```json
{
  "schemaVersion": 1,
  "preset": "mass",
  "clusterSize": 8,
  "shards": [
    {"id":"api","obligationId":"api-findings","prompt":"API 호출부의 오류 근거를 확인한다.","estimatedMinutes":8,"readScope":["src/api"]},
    {"id":"cli","obligationId":"cli-findings","prompt":"CLI 오류 출처를 확인한다.","estimatedMinutes":8,"readScope":["src/cli"]}
  ]
}
```

- 컴파일러는 **읽기 샤드 → 클러스터 리듀서 → 최종 리듀서**를 만들고, 각 리듀서의 필수 멤버를 고정한다. 반환된 상태의 물리 ID를 사용한다. 임의로 준 `leaves`나 예상 명단을 수락 근거로 사용하지 않는다.
- `reduce --run survey --node mass-final --op-id reduce-1`은 엔진의 현재 epoch와 수락된 CAS 영수증으로 대조한다. 누락, 동일 ID의 상이한 digest, 끊어진 역참조가 하나라도 있으면 `partial`이다. 다음 상태에서 다시 축약할 때는 새 작업이므로 새 `opId`를 사용한다.
- 비슷한 실패와 반례를 같은 시그니처로 색인해도 독립 사건과 원본 포인터를 버리지 않는다. 클러스터를 넘는 반증은 원래 샤드 영수증의 항목까지 확인한다. 리듀서에 별도 게이트가 있으면 완전한 색인만으로 게이트를 대체할 수 없다.
- 실측 토큰 예산과 바이트 상한의 선택은 호스트 자료를 따른다. 인라인에서 외부화된 값은 CAS로 조회한다. 실패 개수와 색인 루트는 그대로 유지한다. 식과 폴백은 [장기 작업자 규약](long-worker.md)을 참조한다.
