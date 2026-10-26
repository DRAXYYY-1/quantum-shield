import pytest

from quantum_shield.benchmark import benchmark_case, run_benchmarks


def test_benchmark_reports_integrity_and_storage_overhead():
    result = benchmark_case(4096, 512, replicas=3, repeats=1)
    assert result["integrity_verified"] is True
    assert result["chunk_count"] == 8
    assert result["estimated_storage_bytes"] == 4096 * 3
    assert result["estimated_replication_overhead_bytes"] == 4096 * 2
    assert result["effective_local_mib_per_second"] > 0


def test_benchmark_handles_final_partial_chunk():
    result = benchmark_case(1000, 256, replicas=1, repeats=1)
    assert result["chunk_count"] == 4
    assert result["integrity_verified"] is True


def test_benchmark_rejects_oversized_input():
    with pytest.raises(ValueError, match="size_bytes"):
        benchmark_case(300 * 1024 * 1024, 1024)


def test_benchmark_limits_combinations():
    with pytest.raises(ValueError, match="100"):
        run_benchmarks([1024] * 11, [128] * 10)
