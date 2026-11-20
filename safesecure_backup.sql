--
-- PostgreSQL database dump
--

\restrict oWNxXc3FDeQzNRUTSMI2HcRbw3Ex3ITOYdawhd6Vj43a9aYS80An0lJhnaBiod2

-- Dumped from database version 18.6 (Ubuntu 18.6-0ubuntu0.26.04.1)
-- Dumped by pg_dump version 18.6 (Ubuntu 18.6-0ubuntu0.26.04.1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: vault_storage; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.vault_storage (
    id integer DEFAULT 1 NOT NULL,
    vault_json text NOT NULL,
    trusted_hash text NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE public.vault_storage OWNER TO postgres;

--
-- Data for Name: vault_storage; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.vault_storage (id, vault_json, trusted_hash, updated_at) FROM stdin;
1	{"kvs":{"f5detZaU88O+rhSk/nVuMLFxyDKXspTD3YPDuQIZWVM=":{"iv":"jX2GPtiaJ6EpuC48","ct":"xf4uAI7dRIkEi1lblVJt+8EI8ZTQBcbUGr2F0RYL/LPPLiJusAIVslDs0EqMaH6Bks/RMqtgb4wN6lbCuibTtgn1pgsV7WX/o4jlvIzNdOig"}},"salt":"s1xNb9waBCu7s012rSdsEA==","authTag":"23ZstpY2fMctBIuZwnUYdqAI62Q+i4t5dL28q69gp8s="}	WspLiH5aqsfoHCIJ4WlEQkPY81yH5EQ755cyHNXihGI=	2026-11-20 10:48:17.461292
\.


--
-- Name: vault_storage vault_storage_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.vault_storage
    ADD CONSTRAINT vault_storage_pkey PRIMARY KEY (id);


--
-- PostgreSQL database dump complete
--

\unrestrict oWNxXc3FDeQzNRUTSMI2HcRbw3Ex3ITOYdawhd6Vj43a9aYS80An0lJhnaBiod2

