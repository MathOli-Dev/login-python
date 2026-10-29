# Sistema simples de login (FastAPI + JWT)

Cadastro, login e rota protegida.

## Rodar
```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
export SECRET_KEY="uma-chave-longa-e-aleatoria"   # Windows: set SECRET_KEY=...
uvicorn main:app --reload
```
Documentação interativa: http://localhost:8000/docs

## Rotas
- `POST /register` cria o usuário (senha com hash bcrypt)
- `POST /login` devolve o JWT
- `GET /me` rota protegida (header `Authorization: Bearer <token>`)

## Desafios
1. Refresh token e logout
2. Rate limit no login
3. Roles (user/admin)
4. Sessão com cookie HttpOnly
5. Testes com pytest
