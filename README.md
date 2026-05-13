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
- Classificação 1ª vs 3ª parte por comparação de domínio registrável, com heurística de marca (ex.: `adidas.com` e `adidas.com.br` tratados como mesma parte).

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
- Scripts suspeitos: `-3` por script, com limite mínimo de `-30`.
- Web Storage com dados: `-5` (penalidade única).

Classificação:
- `80-100`: Verde (seguro)
- `50-79`: Amarelo (moderado)
- `0-49`: Vermelho (crítico)

Justificativa resumida:
- Fingerprinting mantém peso alto por maior risco de rastreamento persistente e execução ativa.
- Scripts suspeitos têm peso limitado para evitar saturação em sites com muitos scripts de rastreamento comuns; a heurística exclui CDNs e fornecedores amplamente usados.
- Terceira parte e cookies têm efeito acumulativo, com limite para evitar saturação excessiva.
- Storage tem peso moderado por representar persistência local, sem implicar necessariamente comportamento malicioso.

## Observações técnicas

- A extensão foi projetada para Firefox com Manifest V2 e APIs `webRequest`/`cookies`.
- `data_collection_permissions` descreve coleta local para análise, sem compartilhamento externo.

## Instalação (Firefox)

1. Faça o clone ou o download deste repositório para o seu computador.
2. Abra o Firefox e digite `about:debugging` na barra de endereços.
3. Clique em "This Firefox" (ou "Este Firefox") no menu lateral esquerdo.
4. Clique no botão "Load Temporary Add-on..." (ou "Carregar extensão temporária...").
5. Navegue até a pasta onde você salvou este repositório e selecione o arquivo `manifest.json`.
6. A extensão será instalada temporariamente e o ícone do Privacy Monitor aparecerá na barra de ferramentas do navegador.

## Como Usar

1. Navegue normalmente pela internet.
2. Ao acessar um site, clique no ícone da extensão (um pequeno escudo/ícone na barra superior direita do Firefox).
3. O painel (popup) será aberto exibindo o **Privacy Score** da página atual e detalhando:
   - Quais domínios de terceira parte foram contatados e quais tipos de recursos carregaram.
   - Sinais de sequestro de navegador (Hijacking / Hooking), como scripts suspeitos e redirecionamentos não autorizados.
   - Resumo detalhado do uso de armazenamento local (Web Storage, IndexedDB) e tamanho ocupado.
   - Quantificação de cookies (diferenciando os de 1ª e 3ª parte, sessão/persistentes) e potenciais supercookies detectados.
   - Quais APIs do navegador tentaram ser utilizadas para Fingerprinting (Canvas, WebGL, AudioContext).
4. O *Score* apontará se a página atual é segura (Verde), moderada (Amarela) ou crítica (Vermelha) para a sua privacidade.
