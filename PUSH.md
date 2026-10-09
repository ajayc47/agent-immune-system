# Push to GitHub

From the unzipped folder:

```bash
git init
git add .
git commit -m "Agent Immune System: runtime causal defense for AI agents"
git branch -M main
git remote add origin https://github.com/ajayc47/agent-immune-system.git
git push -u origin main
```

Then run locally to confirm:

```bash
pip install -r requirements.txt
python run.py seed 200
python run.py demo
uvicorn server:app          # dashboard at http://127.0.0.1:8000
```
