--
-- PostgreSQL database dump
--

\restrict p5DckLdytieQcjB55tLpgeW0sknso0G9g6pNQsDR86XvYe23yJ7ZqUO4EOlxtgw

-- Dumped from database version 18.6
-- Dumped by pg_dump version 18.6

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
-- Name: lobot; Type: DATABASE; Schema: -; Owner: lobot
--

CREATE DATABASE lobot WITH TEMPLATE = template0 ENCODING = 'UTF8' LOCALE_PROVIDER = libc LOCALE = 'en_US.utf8';


ALTER DATABASE lobot OWNER TO lobot;

\unrestrict p5DckLdytieQcjB55tLpgeW0sknso0G9g6pNQsDR86XvYe23yJ7ZqUO4EOlxtgw
\connect lobot
\restrict p5DckLdytieQcjB55tLpgeW0sknso0G9g6pNQsDR86XvYe23yJ7ZqUO4EOlxtgw

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
-- Name: DATABASE lobot; Type: COMMENT; Schema: -; Owner: lobot
--

COMMENT ON DATABASE lobot IS 'main db';


--
-- Name: lobot; Type: DATABASE PROPERTIES; Schema: -; Owner: lobot
--

ALTER DATABASE lobot SET "TimeZone" TO 'America/Sao_Paulo';
ALTER ROLE lobot_app IN DATABASE lobot SET work_mem TO '8MB';


\unrestrict p5DckLdytieQcjB55tLpgeW0sknso0G9g6pNQsDR86XvYe23yJ7ZqUO4EOlxtgw
\connect lobot
\restrict p5DckLdytieQcjB55tLpgeW0sknso0G9g6pNQsDR86XvYe23yJ7ZqUO4EOlxtgw

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
-- Name: t; Type: TABLE; Schema: public; Owner: lobot
--

CREATE TABLE public.t (
    id integer
);


ALTER TABLE public.t OWNER TO lobot;

--
-- Name: DATABASE lobot; Type: ACL; Schema: -; Owner: lobot
--

REVOKE CONNECT,TEMPORARY ON DATABASE lobot FROM PUBLIC;
GRANT TEMPORARY ON DATABASE lobot TO PUBLIC;
GRANT CONNECT,TEMPORARY ON DATABASE lobot TO lobot_app;


--
-- PostgreSQL database dump complete
--

\unrestrict p5DckLdytieQcjB55tLpgeW0sknso0G9g6pNQsDR86XvYe23yJ7ZqUO4EOlxtgw

