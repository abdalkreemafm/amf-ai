/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_AMF_API?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
