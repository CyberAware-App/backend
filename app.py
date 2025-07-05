from fastapi import FastAPI
from pydantic import BaseModel, Field
from fastapi.middleware.cors import CORSMiddleware
from db import models, database
from routers import auth

app = FastAPI(title="CyberAware Backend", description="CyberAware Backend API", version="0.1.0")

app.add_middleware(
   CORSMiddleware,
   allow_origins=["*"],
   allow_credentials=True,
   allow_methods=["*"],
   allow_headers=["*"],
)

# Include routers
app.include_router(auth.router)

@app.get("/")
def read_root():
    return {"Hello": "World"}

if __name__ == "__main__":
    import uvicorn
    models.Base.metadata.create_all(bind=database.engine)
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)