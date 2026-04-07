# NVIDIA DGX Spark — Max's Production Setup

## Hardware
- NVIDIA GB10 Grace Blackwell Superchip
- 128GB LPDDR5x unified memory (shared CPU/GPU)
- 1-4TB NVMe SSD (PCIe Gen5)
- 10 GbE Ethernet + WiFi 7 + 2x QSFP 200Gb
- Ubuntu 24.04 (DGX OS 7)
- Docker + NVIDIA Container Runtime pre-installed
- 240W peak, desktop form factor (150x150x50mm, 1.2kg)

## Current Model: Nemotron Cascade 2 30B
- **Model:** chankhavu/Nemotron-Cascade-2-30B-A3B-NVFP4
- **Architecture:** 30B MoE / 3B active parameters, hybrid Mamba-Attention
- **Quantization:** NVFP4 (19GB on disk, ~125GB in URAM at runtime)
- **HuggingFace:** https://huggingface.co/chankhavu/Nemotron-Cascade-2-30B-A3B-NVFP4

## Container & Run Command
```bash
# Drop page cache before starting (ALWAYS do this first)
sudo sh -c 'echo 3 > /proc/sys/vm/drop_caches'

docker run -d \
  --name nemotron-cascade2-nvfp4 \
  --gpus all \
  --ipc=host \
  --ulimit memlock=-1 \
  --ulimit stack=67108864 \
  --restart=no \
  -e VLLM_USE_FLASHINFER_MOE_FP4=0 \
  -v /path/to/Nemotron-Cascade-2-30B-A3B-NVFP4:/models/cascade2-nvfp4 \
  -p 8901:8000 \
  nvcr.io/nvidia/vllm:26.03-py3 \
  python3 -m vllm.entrypoints.openai.api_server \
    --model /models/cascade2-nvfp4 \
    --served-model-name nemotron-cascade-2 \
    --trust-remote-code \
    --max-model-len 262144 \
    --gpu-memory-utilization 0.92 \
    --mamba-ssm-cache-dtype float32 \
    --kv-cache-dtype fp8 \
    --reasoning-parser nemotron_v3 \
    --enable-auto-tool-choice \
    --tool-call-parser qwen3_coder \
    --enable-chunked-prefill
```

## Critical Settings
- `VLLM_USE_FLASHINFER_MOE_FP4=0` — MANDATORY on GB10 Spark. Without this, FLASHINFER_CUTLASS MoE kernels crash with illegal instruction on SM120. Forces MARLIN backend.
- `--mamba-ssm-cache-dtype float32` — required for hybrid Mamba layers
- `--kv-cache-dtype fp8` — matches quantization recipe
- `--reasoning-parser nemotron_v3` — enables thinking mode (content in `<think>` tags)
- `--enable-auto-tool-choice` + `--tool-call-parser qwen3_coder` — enables function/tool calling

## Performance Benchmarks
| Metric | Value |
|--------|-------|
| Single request speed | 59.2 tok/s |
| Time to first token | 186ms |
| Peak throughput (c=32) | 643 system tok/s |
| Context window | 262,144 tokens |
| KV cache | 6.37M tokens |
| Tested requests | 600+ |
| Error rate | 0% |
| Memory footprint | ~125GB / 128GB (0.92 utilization) |

## API
- **Type:** OpenAI-compatible (vLLM serves /v1/chat/completions)
- **Port:** 8901
- **Model name:** nemotron-cascade-2
- **Base URL:** http://DGX_SPARK_IP:8901/v1
- **Tool calling:** Supported (qwen3_coder parser)
- **Reasoning:** Supported (nemotron_v3, `<think>` tags)

## Integration with Command Base
- Simple/normal tasks → local Nemotron (zero cost, 59 tok/s)
- Complex/urgent tasks → Claude API (Opus/Sonnet)
- Routing decisions → local (262K context handles full team roster)
- Peer reviews → local
- QA checks → local
- Research tasks → local or Claude depending on complexity
- Code generation → Claude API (higher quality)

## Estimated Cost Savings
- Current: ~$15-30/day on Claude API
- After DGX: ~$3-5/day (only complex tasks hit Claude)
- Savings: 70-85% reduction in API costs
