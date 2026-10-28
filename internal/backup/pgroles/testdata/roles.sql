-- hangar-bootstrap-superuser: 6c6f626f74
--
-- PostgreSQL database cluster dump
--

\restrict 6Fs5k7GXYCAZ2OkjD5SPRdKF6hbdPClrcjF6052SrLf86nrAs9zwKd2hVhD5EKj

SET default_transaction_read_only = off;

SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;

--
-- Roles
--

CREATE ROLE "Odd ""Name""";
ALTER ROLE "Odd ""Name""" WITH NOSUPERUSER INHERIT NOCREATEROLE NOCREATEDB NOLOGIN NOREPLICATION NOBYPASSRLS;
CREATE ROLE lobot;
ALTER ROLE lobot WITH SUPERUSER INHERIT CREATEROLE CREATEDB LOGIN REPLICATION BYPASSRLS PASSWORD 'SCRAM-SHA-256$4096:/2PZMldNVPuQCLgyp++CHg==$kzh4Ihv0uhTHswUuJureDwdy7HINV+nTX7gwtoUUykI=:Pgmv1B1zZEt9VOxNegmIxdo8/YJodxIU2Ss4W6PpbIQ=';
CREATE ROLE lobot_app;
ALTER ROLE lobot_app WITH NOSUPERUSER INHERIT NOCREATEROLE NOCREATEDB LOGIN NOREPLICATION NOBYPASSRLS PASSWORD 'SCRAM-SHA-256$4096:RRpxR2VdCYpnpX71a4tFMw==$kiIo4DLebeUKvPqU5UwDOsydVNLGs/mEsp9rHKnL4JU=:hawARHwWDbC4ia6C+UEsrHOXdbopoevcHFwMur/Mplk=';
COMMENT ON ROLE lobot_app IS 'the app';
CREATE ROLE lobot_system;
ALTER ROLE lobot_system WITH NOSUPERUSER INHERIT NOCREATEROLE NOCREATEDB LOGIN NOREPLICATION BYPASSRLS CONNECTION LIMIT 5 PASSWORD 'SCRAM-SHA-256$4096:4So6OPe7XZOxTaJBEzvBSg==$DfnDbPrblt7Vat4f3bdhI+2Qcw3eRuZ7eTeiobbCc80=:Dmuz3u5uiR3rvBTwoUDIHPw2zqMNNzRrE1rXDKsLbdg=' VALID UNTIL '2029-12-31 21:00:00-03';

--
-- User Configurations
--

--
-- User Config "lobot_app"
--

ALTER ROLE lobot_app SET statement_timeout TO '5s';
ALTER ROLE lobot_app SET search_path TO 'app', 'public';


--
-- Role memberships
--

GRANT lobot_app TO lobot_system WITH INHERIT TRUE GRANTED BY lobot;




\unrestrict 6Fs5k7GXYCAZ2OkjD5SPRdKF6hbdPClrcjF6052SrLf86nrAs9zwKd2hVhD5EKj

--
-- PostgreSQL database cluster dump complete
--

