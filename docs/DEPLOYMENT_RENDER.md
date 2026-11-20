# PromptShield AI — Render Backend Deployment Guide

This guide details the step-by-step procedure to deploy the PromptShield AI FastAPI backend to [Render](https://render.com).

---

## 1. Prerequisites
- A Render account (free tier available at [render.com](https://render.com)).
- Your PromptShield AI repository on GitHub: `https://github.com/sushanthns05/PromptShield-AI`.

---

## 2. Deployment Method A: 1-Click Render Blueprint (Recommended)

The repository includes a ready-to-use [`render.yaml`](../render.yaml) blueprint specification.

1. Log into your Render dashboard.
2. Click **New +** in the top navigation bar and select **Blueprint**.
3. Connect your GitHub repository `sushanthns05/PromptShield-AI`.
4. Render will automatically parse `render.yaml` and configure:
   - **Service Name**: `promptshield-ai-backend`
   - **Environment**: Python 3.11
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn backend.app.main:app --host 0.0.0.0 --port $PORT`
   - **Allowed Origins**: `https://pomptshieldai.web.app`, `https://pomptshieldai.firebaseapp.com`
5. Click **Apply**. Render will automatically build the container and deploy your live FastAPI instance.

---

## 3. Deployment Method B: Manual Web Service Setup

If you prefer to configure the Web Service manually:

1. In the Render Dashboard, click **New +** $\rightarrow$ **Web Service**.
2. Select **Build and deploy from a Git repository** $\rightarrow$ Connect `PromptShield-AI`.
3. Fill in the following deployment parameters:

| Field | Configuration Value |
|---|---|
| **Name** | `promptshield-ai-backend` (or your preferred name) |
| **Region** | Oregon (US West) or your closest region |
| **Branch** | `main` |
| **Root Directory** | *(leave empty - repository root)* |
| **Runtime** | `Python 3` |
| **Build Command** | `pip install -r requirements.txt` |
| **Start Command** | `uvicorn backend.app.main:app --host 0.0.0.0 --port $PORT` |
| **Instance Type** | Free |

4. In the **Environment Variables** section, add:

| Key | Value | Description |
|---|---|---|
| `PYTHON_VERSION` | `3.12.8` | Ensures compatible Python runtime (supports Python 3.11 and 3.12) |
| `PROMPTSHIELD_ALLOWED_ORIGINS` | `https://pomptshieldai.web.app,https://pomptshieldai.firebaseapp.com,http://localhost:3000` | Enables CORS for your Firebase frontend |
| `PROMPTSHIELD_DATASET_PATH` | `research/datasets/prompts.csv` | Relative path to prompts dataset |

5. Click **Create Web Service**.

---

## 4. Verifying Backend Deployment

Once the build finishes and shows `Live`:

1. Copy your assigned Render service URL (e.g., `https://promptshield-ai-backend.onrender.com`).
2. Test the health endpoint in your browser or terminal:
   ```bash
   curl https://promptshield-ai-backend.onrender.com/api/v1/health
   ```
   **Expected Response**:
   ```json
   {
     "status": "healthy",
     "version": "0.1.0",
     "classifier_loaded": true,
     "document_scanner_loaded": true,
     "active_session_contexts": 0
   }
   ```
3. Test OpenAPI documentation:
   Open `https://promptshield-ai-backend.onrender.com/docs` in your browser.

---

## 5. Connecting Firebase Frontend to Render Backend

Once your backend is live on Render:

1. Open your live Firebase frontend: [https://pomptshieldai.web.app/](https://pomptshieldai.web.app/)
2. Click the **Settings** gear icon in the top right navigation bar.
3. In the **Backend API URL** field, paste your Render URL:
   ```text
   https://promptshield-ai-backend.onrender.com
   ```
4. Click **Test** $\rightarrow$ verify that it returns `Connected successfully! Status: healthy`.
5. Click **Save Endpoint**.

Your live Firebase dashboard is now actively communicating with your cloud-hosted Render backend gateway!
