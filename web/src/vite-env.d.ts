/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Optional absolute API origin, e.g. https://network-map.onrender.com */
  readonly VITE_API_BASE?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}