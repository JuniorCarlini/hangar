--
-- PostgreSQL database dump
--

\restrict 5kz5Q4o6daKgyAUaQIoIwH0ooPar0uBgEi9U7twLODXq8S28osuxXsq4oPGKBAC

-- Dumped from database version 18.6 (Debian 18.6-1.pgdg13+2)
-- Dumped by pg_dump version 18.6 (Debian 18.6-1.pgdg13+2)

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
-- Name: pedidos; Type: TABLE; Schema: public; Owner: lobot
--

CREATE TABLE public.pedidos (
    id integer NOT NULL,
    tenant integer,
    valor integer
);


ALTER TABLE public.pedidos OWNER TO lobot;

--
-- Name: pedidos_id_seq; Type: SEQUENCE; Schema: public; Owner: lobot
--

CREATE SEQUENCE public.pedidos_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.pedidos_id_seq OWNER TO lobot;

--
-- Name: pedidos_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: lobot
--

ALTER SEQUENCE public.pedidos_id_seq OWNED BY public.pedidos.id;


--
-- Name: pedidos id; Type: DEFAULT; Schema: public; Owner: lobot
--

ALTER TABLE ONLY public.pedidos ALTER COLUMN id SET DEFAULT nextval('public.pedidos_id_seq'::regclass);


--
-- Name: pedidos pedidos_pkey; Type: CONSTRAINT; Schema: public; Owner: lobot
--

ALTER TABLE ONLY public.pedidos
    ADD CONSTRAINT pedidos_pkey PRIMARY KEY (id);


--
-- Name: pedidos; Type: ROW SECURITY; Schema: public; Owner: lobot
--

ALTER TABLE public.pedidos ENABLE ROW LEVEL SECURITY;

--
-- Name: pedidos sys; Type: POLICY; Schema: public; Owner: lobot
--

CREATE POLICY sys ON public.pedidos TO lobot_system USING (true) WITH CHECK (true);


--
-- Name: pedidos tenant_iso; Type: POLICY; Schema: public; Owner: lobot
--

CREATE POLICY tenant_iso ON public.pedidos FOR SELECT TO lobot_app, "Weird ""Role""" USING ((tenant = (current_setting('app.tenant'::text, true))::integer));


--
-- Name: SCHEMA public; Type: ACL; Schema: -; Owner: pg_database_owner
--

GRANT USAGE ON SCHEMA public TO lobot_app;
GRANT USAGE ON SCHEMA public TO lobot_system;


--
-- Name: FUNCTION now(); Type: ACL; Schema: pg_catalog; Owner: lobot
--

REVOKE ALL ON FUNCTION pg_catalog.now() FROM PUBLIC;


--
-- Name: TABLE pedidos; Type: ACL; Schema: public; Owner: lobot
--

GRANT SELECT,INSERT ON TABLE public.pedidos TO lobot_app;
GRANT ALL ON TABLE public.pedidos TO lobot_system WITH GRANT OPTION;


--
-- Name: COLUMN pedidos.valor; Type: ACL; Schema: public; Owner: lobot
--

GRANT SELECT(valor) ON TABLE public.pedidos TO "Weird ""Role""";


--
-- Name: SEQUENCE pedidos_id_seq; Type: ACL; Schema: public; Owner: lobot
--

GRANT USAGE ON SEQUENCE public.pedidos_id_seq TO lobot_app;


--
-- Name: DEFAULT PRIVILEGES FOR SEQUENCES; Type: DEFAULT ACL; Schema: public; Owner: lobot
--

ALTER DEFAULT PRIVILEGES FOR ROLE lobot IN SCHEMA public GRANT USAGE ON SEQUENCES TO "Weird ""Role""";


--
-- Name: DEFAULT PRIVILEGES FOR TABLES; Type: DEFAULT ACL; Schema: public; Owner: lobot
--

ALTER DEFAULT PRIVILEGES FOR ROLE lobot IN SCHEMA public GRANT SELECT ON TABLES TO lobot_app;


--
-- PostgreSQL database dump complete
--

\unrestrict 5kz5Q4o6daKgyAUaQIoIwH0ooPar0uBgEi9U7twLODXq8S28osuxXsq4oPGKBAC

