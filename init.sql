CREATE TABLE public.app_user (
    id uuid NOT NULL,
    username text NOT NULL,
    email text NOT NULL,
    password text NOT NULL
);


ALTER TABLE public.app_user OWNER TO postgres;

CREATE TABLE public.user_session (
    id text NOT NULL,
    user_id uuid NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    expires_at timestamp without time zone NOT NULL
);


ALTER TABLE public.user_session OWNER TO postgres;

ALTER TABLE ONLY public.app_user
    ADD CONSTRAINT app_user_email_key UNIQUE (email);

ALTER TABLE ONLY public.app_user
    ADD CONSTRAINT app_user_pkey PRIMARY KEY (id);


ALTER TABLE ONLY public.user_session
    ADD CONSTRAINT user_session_pkey PRIMARY KEY (id);


ALTER TABLE ONLY public.user_session
    ADD CONSTRAINT user_session_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.app_user(id) ON DELETE CASCADE;



