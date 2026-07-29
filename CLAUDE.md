# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Personal portfolio + tech blog (0xbites.github.io) built on Jekyll using the **Chirpy theme as a gem** (`jekyll-theme-chirpy`). Most layouts, includes, and CSS live inside the gem, **not in this repo** — the repo is intentionally thin (content + config + a few overrides). To customize a layout or include, copy it out of the installed gem (`bundle info jekyll-theme-chirpy` → path) into a matching path here; there is no local copy to edit otherwise.

## Commands

- `bundle install` — install dependencies.
- `bundle exec jekyll serve` — local server at `http://127.0.0.1:4000`. Prefer `tools/run.sh` (adds livereload `-l` and auto-enables `--force_polling` when running inside Docker); `tools/run.sh -p` for a production-env serve.
- `tools/test.sh` — **the CI gate, run before pushing.** Does a production `jekyll b` then `htmlproofer` on `_site` (external links disabled). Broken *internal* links fail this and therefore fail deploy.
- Deploy: push to `main` → `.github/workflows/pages-deploy.yml` rebuilds and publishes to GitHub Pages. There is no manual deploy step.

If `bundle` isn't on PATH, use `$(gem env user_gembin)/bundle ...`.

## Non-obvious things to know

- **Deploy is a custom Actions workflow, not GitHub's default Pages build.** It runs the same `jekyll b` + `htmlproofer` as `tools/test.sh`, so a green `tools/test.sh` locally is the real pre-push check.
- **`last_modified_at` is derived from git history**, not front matter — `_plugins/posts-lastmod-hook.rb` reads `git log` for each post. This needs full history (CI uses `fetch-depth: 0`); a shallow clone silently drops lastmod dates.
- **Ruby version mismatch is expected:** local `.ruby-version` pins **3.3.12**, CI (`pages-deploy.yml`) uses **3.4**. Match CI when reproducing build issues.
- **`assets/lib` is a git submodule** (chirpy-static-assets) but CI does **not** initialize it (the `submodules: true` line is commented out), so the deployed site uses the theme's default asset source, not the submodule.
- `_config.yml` `exclude:` drops `tools/`, `README.md`, `LICENSE`, and config JS from the build — files there are not published.

## Content conventions

- **Posts:** `_posts/YYYY-MM-DD-title.md`. Front matter follows the existing posts: `title`, `date` (with `+0000`), `categories: [A, B]`, `tags: [...]`, `description`, optional `image.path`, `toc: true`. Post permalink is fixed to `/posts/:title/` in `_config.yml` — don't change it (other links depend on it).
- **Tabs/pages:** `_tabs/*.md` is the `tabs` collection (about, projects, credentials, …), rendered as `page` and ordered by front-matter `order`.
- `_data/` holds `contact.yml` and `share.yml` (sidebar contact links and post share targets).
