# Diagramas da Auditoria — urban-hack-sentinel

## Diagrama de Fluxo de Dados/Arquitetura de Alto Nível

```mermaid
graph TD
    A[CLI] -->|Comandos| B[Core]
    B -->|Processamento| C[Web API]
    C -->|Respostas| A
    C -->|Relatórios| D[Base de Dados]
    D -->|Dados| C
```

## Grafo de Dependências entre Módulos/Pacotes Internos

```mermaid
graph TD
    E[core] -->|Importa| F[web]
    F -->|Importa| E
    G[cli] -->|Importa| E
```

## Notas sobre os Diagramas
- O diagrama de fluxo de dados mostra a interação entre a CLI, o Core, a Web API e a Base de Dados.
- O grafo de dependências destaca o ciclo de dependência entre `core` e `web`.
