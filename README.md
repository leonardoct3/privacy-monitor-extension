Extensão validada em ambiente controlado

# privacy-monitor-extension

Extensão para navegador Firefox para detecção de ameaças à privacidade e rastreamento em cliente web.

## Arquitetura

- `manifest.json`: configuração da WebExtension (Manifest V2), permissões e vínculos de scripts.
- `privacy_monitor.js`: script de background para interceptação de requisições, cookies, sinais de supercookie e cálculo de score.
- `content_script.js`: instrumentação de APIs de fingerprinting, captura de eventos de redirecionamento e inspeção de storage.
- `popup/popup.html` + `popup/popup.js`: interface para visualizar evidências e score de privacidade.

## Funcionalidades

1. Conexões de terceira parte
- Interceptação via `webRequest`.
- Classificação por tipo de recurso (`script`, `image`, `sub_frame`, `xmlhttprequest`, etc.).
- Classificação 1ª vs 3ª parte por comparação de domínio registrável.

2. Detecção de hijacking/hooking
- Sinalização de scripts externos suspeitos por origem não relacionada ao site atual.
- Detecção de redirecionamentos por `window.location.assign`, `replace` e setter de `href`.

3. Web Storage e IndexedDB
- Inspeção de `localStorage`, `sessionStorage` e inventário básico de IndexedDB.
- Exibição de chaves e tamanho estimado por domínio da aba.

4. Cookies e supercookies
- Listagem de cookies da aba atual via API de cookies.
- Diferenciação 1ª/3ª parte e sessão/persistente.
- Sinais heurísticos de supercookie: HSTS e ETag.

5. Fingerprinting
- Interceptação de APIs:
  - Canvas: `toDataURL`, `getImageData`
  - WebGL: `getParameter`, `WEBGL_debug_renderer_info`
  - AudioContext: `createOscillator`, `createDynamicsCompressor`
- Registro de tentativas e envio para o background.

## Metodologia do Privacy Score

Pontuação base: `100` (mínimo `0`).

Pesos:
- Domínios de 3ª parte: `-3` por domínio, com limite mínimo de `-30`.
- Fingerprinting detectado: `-20` por técnica (Canvas, WebGL, Audio).
- Cookies de 3ª parte: `-5` por cookie, com limite mínimo de `-15`.
- Scripts suspeitos: `-10` por script.
- Web Storage com dados: `-5` (penalidade única).

Classificação:
- `80-100`: Verde (seguro)
- `50-79`: Amarelo (moderado)
- `0-49`: Vermelho (crítico)

Justificativa resumida:
- Fingerprinting e scripts suspeitos recebem maior peso por maior risco de rastreamento persistente e execução ativa.
- Terceira parte e cookies têm efeito acumulativo, com limite para evitar saturação excessiva.
- Storage tem peso moderado por representar persistência local, sem implicar necessariamente comportamento malicioso.

## Observações técnicas

- A extensão foi projetada para Firefox com Manifest V2 e APIs `webRequest`/`cookies`.
- `data_collection_permissions` descreve coleta local para análise, sem compartilhamento externo.
