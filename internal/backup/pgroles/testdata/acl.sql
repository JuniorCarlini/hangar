--
-- PostgreSQL database dump
--

\restrict H2TQxhgA42MMX5JWlrn1WXBw7BQ2CoG76bO3Xn6JV0XqnCXoNmfN4lqJcZBRI5h

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

\unrestrict H2TQxhgA42MMX5JWlrn1WXBw7BQ2CoG76bO3Xn6JV0XqnCXoNmfN4lqJcZBRI5h

