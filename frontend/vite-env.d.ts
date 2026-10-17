declare module 'vite/client' { export interface ImportMetaEnv { [key: string]: any; readonly BASE_URL: string } interface ImportMeta { readonly env: ImportMetaEnv } }
