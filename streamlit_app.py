"""로그 분석기 + AI 해설 (Streamlit Community Cloud 배포용)

구조
1) 탐지는 기존 log_analyzer.py 의 규칙 기반 로직이 한다. (판정의 근거)
2) AI 는 그 결과를 한국어 보고서로 풀어 설명만 한다.
   → AI 가 틀려도 탐지 결과 자체는 바뀌지 않게 역할을 나눴다.
3) AI 엔진은 두 가지 중 고른다.
   - HF API: Inference Providers 서버에 요청 (크레딧 필요, 기본값)
   - 로컬: HF Hub 에서 받은 작은 모델을 내 컴퓨터에서 직접 실행
           (무료, torch·transformers 를 따로 설치해야 함)
4) AI 에 보낼 보고서·프롬프트는 ai_report.py 가 만든다. (Streamlit 없이 테스트하려고 분리)

실행: streamlit run streamlit_app.py
"""
import io
import os
from pathlib import Path

import streamlit as st
from huggingface_hub import InferenceClient

import ai_report
import log_analyzer as la

DEFAULT_MODEL = "Qwen/Qwen3.5-9B"   # HF API 용. 바꾸려면 secrets.toml 에 MODEL_ID = "..." 추가
DEFAULT_LOCAL_MODEL = "Qwen/Qwen2.5-1.5B-Instruct"   # 로컬용. LOCAL_MODEL_ID 로 변경 가능
MAX_FILE_BYTES = 5 * 1024 * 1024   # 업로드 허용 크기 5MB
DEMO_LOG = Path(__file__).parent / "demo_attack.log"


def get_setting(name, default=None):
    """설정값 읽기: Streamlit Secrets → 환경변수 순서로 찾는다.

    st.secrets 는 secrets 파일이 아예 없으면 예외를 내므로 try 로 감싼다.
    """
    try:
        if name in st.secrets:
            return st.secrets[name]
    except Exception:
        pass
    return os.getenv(name, default)


# ===== 엔진 1: HF API (남의 서버) =====
# 같은 보고서를 다시 물으면 API 를 또 부르지 않고 저장해 둔 답을 쓴다 (크레딧 절약)
# 성공한 답만 저장된다: 함수 안에서 예외가 나면 cache_data 는 결과를 저장하지 않는다.
# _token 처럼 이름 앞에 _ 를 붙인 인자는 캐시 키 계산에서 빠진다 (토큰을 키로 쓰지 않게).
@st.cache_data(show_spinner=False, ttl=3600)
def call_api(report, model_id, _token):
    client = InferenceClient(token=_token)
    response = client.chat_completion(
        model=model_id,
        messages=ai_report.build_messages(report),
        max_tokens=1500,
        temperature=0.2,   # 낮을수록 답이 일정하고 덜 지어낸다
    )
    return ai_report.clean_answer(response.choices[0].message.content)


# ===== 엔진 2: 로컬 모델 (내 맥) =====
# cache_resource: 모델처럼 '무겁고 한 번만 만들면 되는 객체'를 앱이 켜져 있는 동안 메모리에 유지한다.
# 이게 없으면 버튼을 누를 때마다(=스크립트가 다시 돌 때마다) 3GB 모델을 새로 읽는다.
@st.cache_resource(show_spinner=False)
def load_local_model(model_id):
    # torch·transformers 는 여기서만 불러온다.
    # 맨 위에서 import 하면, 로컬 엔진을 안 쓰는 배포 환경에서도 설치가 필요해진다.
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer

    device = "mps" if torch.backends.mps.is_available() else "cpu"
    tokenizer = AutoTokenizer.from_pretrained(model_id)
    model = AutoModelForCausalLM.from_pretrained(
        model_id,
        dtype=torch.float16 if device == "mps" else torch.float32,
    ).to(device)
    return tokenizer, model, device


@st.cache_data(show_spinner=False, ttl=3600)
def call_local(report, model_id):
    tokenizer, model, device = load_local_model(model_id)
    # 채팅 템플릿으로 대화를 한 줄 글로 만든 뒤 → 다음 토큰을 이어 붙여 생성한다
    prompt = tokenizer.apply_chat_template(ai_report.build_messages(report), tokenize=False,
                                           add_generation_prompt=True)
    inputs = tokenizer(prompt, return_tensors="pt").to(device)
    output = model.generate(**inputs, max_new_tokens=500, do_sample=True, temperature=0.2)
    new_tokens = output[0][inputs["input_ids"].shape[1]:]
    return ai_report.clean_answer(tokenizer.decode(new_tokens, skip_special_tokens=True))


def ask_ai(report, engine):
    """엔진을 골라 호출한다. 에러 처리는 캐시 밖에서 해서 실패 메시지가 캐시에 남지 않게."""
    try:
        if engine == "로컬":
            model_id = get_setting("LOCAL_MODEL_ID", DEFAULT_LOCAL_MODEL)
            return call_local(report, model_id), model_id
        model_id = get_setting("MODEL_ID", DEFAULT_MODEL)
        token = get_setting("HF_TOKEN")
        if not token:
            return ("⚠️ HF_TOKEN 이 설정되지 않아 AI 해설을 건너뛰었습니다. "
                    "(.streamlit/secrets.toml 또는 앱 설정 → Secrets)"), model_id
        return call_api(report, model_id, token), model_id
    except ModuleNotFoundError:
        return "⚠️ 로컬 엔진에는 torch 와 transformers 설치가 필요합니다.", "-"
    except Exception as e:  # 모델 미지원·크레딧 부족·메모리 부족 등
        return f"⚠️ AI 해설 실패: {type(e).__name__}: {e}", "-"


# ---------------- 화면 ----------------
st.set_page_config(page_title="로그 분석기 + AI 해설", page_icon="🔍", layout="wide")
st.title("🔍 로그 분석기 + AI 해설")
st.caption("규칙 기반으로 브루트포스(급속·완속)와 민감파일 접근을 탐지하고, "
           "AI 가 결과를 한국어 보고서로 풀어 설명합니다.")
st.code("2024-01-15 09:25:01 LOGIN_FAIL user=root ip=10.0.0.5", language=None)

uploaded = st.file_uploader("로그 파일 (.log / .txt)", type=["log", "txt"])
use_ai = st.toggle("AI 해설 사용", value=True)
# 기본값은 HF API. 로컬 엔진은 torch·transformers 가 따로 필요해 배포 환경에서는 동작하지 않는다.
engine = st.radio("AI 엔진", ["HF API", "로컬"], horizontal=True,
                  help="HF API: 큰 모델을 서버에서 실행(크레딧 필요) / 로컬: 내 컴퓨터에서 작은 모델 실행(torch·transformers 필요)")
col_run, col_demo = st.columns(2)
run_clicked = col_run.button("분석하기", type="primary", width="stretch")
demo_clicked = col_demo.button("샘플 로그로 실행", width="stretch")

lines = None
if demo_clicked:
    lines = DEMO_LOG.read_text(encoding="utf-8").splitlines()
elif run_clicked:
    if uploaded is None:
        st.warning("로그 파일을 먼저 올려주세요.")
    elif uploaded.size > MAX_FILE_BYTES:
        st.error("파일이 너무 큽니다. (최대 5MB)")
    else:
        # 업로드 파일은 바이트로 오므로 글자로 바꾼다. 깨진 바이트는 대체 문자로.
        # utf-8-sig: 윈도우 메모장 등이 붙이는 BOM 을 떼고 읽는다 (안 떼면 첫 줄 시각을 못 읽음)
        lines = io.TextIOWrapper(uploaded, encoding="utf-8-sig", errors="replace")

if lines is not None:
    result = la.analyze(lines)   # CLI 와 같은 분석 함수
    report = result.report()
    alert_count = len(result.alerts)
    left, right = st.columns(2)
    with left:
        st.subheader("탐지 결과 (규칙 기반)")
        if alert_count:
            st.error(f"경고 {alert_count}건")
        else:
            st.success("이상 없음")
        st.code(report, language=None)
    with right:
        st.subheader("AI 해설")
        if use_ai:
            msg = "AI 가 분석 중... (로컬 첫 실행은 모델을 불러오느라 30초~1분 걸려요)"
            with st.spinner(msg):
                answer, model_id = ask_ai(ai_report.report_for_ai(result), engine)
            st.markdown(answer)
            st.caption(f"엔진: {engine} · 모델: {model_id} · "
                       "AI 해설은 참고용이며 판정은 왼쪽 결과가 기준입니다.")
        else:
            st.info("AI 해설이 꺼져 있습니다.")
