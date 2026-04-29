# Personal blog — Jekyll + Chirpy + bilingual (EN / VI)

Static-site blog hosted on GitHub Pages.
- Theme: [Chirpy](https://github.com/cotes2020/jekyll-theme-chirpy)
- Languages: English (`/en/`) and Tiếng Việt (`/vi/`)
- CI/CD: GitHub Actions → GitHub Pages

---

## First-time setup

### 1. Replace placeholders

Open `_config.yml` and replace every `YOUR_GITHUB_USERNAME` with your actual
GitHub username. Update `title`, `tagline`, `description`, `social.name`,
and `social.email` while you're there.

Same for `_tabs/about.md`.

### 2. Local dev environment

You need Ruby 3.1+ and Bundler.

```bash
# macOS (with Homebrew)
brew install rbenv ruby-build
rbenv install 3.3.0
rbenv global 3.3.0

# Ubuntu/Debian
sudo apt install -y ruby-full build-essential zlib1g-dev

# Windows
# Use RubyInstaller from https://rubyinstaller.org/ — install with DevKit
```

Then in this folder:

```bash
bundle install
bundle exec jekyll serve --livereload
```

Open <http://127.0.0.1:4000>. Saves to `.md` files trigger a rebuild.

### 3. Push to GitHub

Create a repo named `YOUR_GITHUB_USERNAME.github.io` (the repo name must match
your username exactly for GitHub Pages to serve it at the root URL).

```bash
git init -b main
git add .
git commit -m "Initial commit"
git remote add origin git@github.com:YOUR_GITHUB_USERNAME/YOUR_GITHUB_USERNAME.github.io.git
git push -u origin main
```

### 4. Enable GitHub Pages

On the repo page → **Settings** → **Pages** → under **Source**, select
**GitHub Actions**. The workflow in `.github/workflows/pages-deploy.yml`
will build and deploy on every push to `main`.

After the first successful deploy (~1 minute), the site is live at
<https://YOUR_GITHUB_USERNAME.github.io>.

---

## Writing posts

### English post

Create `_en/_posts/YYYY-MM-DD-slug.md`:

```yaml
---
title: "Post title"
date: 2026-04-27 10:00:00 +0700
categories: [Malware Analysis]
tags: [reverse-engineering, ida-pro]
translation_key: my-post-slug    # ← used to link to the Vietnamese version
description: >-
  One-line description for SEO and social previews.
---

Post body in Markdown.
```

### Vietnamese counterpart

Create `_vi/_posts/YYYY-MM-DD-slug.md` with the **same `translation_key`**.
The language switcher will automatically link the two.

### Post frontmatter cheatsheet

| Key | Notes |
|-----|-------|
| `title` | Required |
| `date` | `YYYY-MM-DD HH:MM:SS +TIMEZONE` |
| `categories` | List, max 2 levels deep |
| `tags` | Free-form list |
| `translation_key` | **Same value** in both EN and VI versions |
| `description` | Used in `<meta>` and social cards |
| `image.path` | Cover image (1200×630 ideal) |
| `pin: true` | Pin to top of listing |
| `math: true` | Enable MathJax for this post |
| `mermaid: true` | Enable Mermaid diagrams |

---

## Folder layout

```
.
├── _config.yml                  # site config + bilingual collections
├── _en/_posts/                  # English posts
├── _vi/_posts/                  # Vietnamese posts
├── _tabs/                       # sidebar tabs (about, archives, …)
├── _includes/lang-switcher.html # the EN ⇄ VI toggle
├── _layouts/post.html           # wraps Chirpy's post layout + injects switcher
├── _layouts/redirect.html       # used by the root / → /en/ redirect
├── assets/img/                  # images (avatar, post covers, …)
├── en.md                        # /en/ landing page
├── vi.md                        # /vi/ landing page
├── index.md                     # / → redirects to /en/
└── .github/workflows/           # CI/CD
```

---

## Custom domain (later)

When you buy a domain (e.g. `yourhandle.dev`):

1. Create a `CNAME` file at the repo root containing just `yourhandle.dev`
2. At your DNS provider, add:
   - `A` records for the apex pointing to GitHub Pages IPs
     (185.199.108.153, 185.199.109.153, 185.199.110.153, 185.199.111.153)
   - `CNAME` for `www` → `YOUR_GITHUB_USERNAME.github.io`
3. In **Settings** → **Pages**, set the custom domain and enable HTTPS
4. Update `_config.yml` → `url: "https://yourhandle.dev"`

---

## Troubleshooting

**Build fails locally with "Could not find gem":** run `bundle install` again.

**`jekyll serve` shows old content:** delete `_site/` and `.jekyll-cache/`,
then rerun.

**Vietnamese characters render as `?`:** every file must be UTF-8 (no BOM).
On Windows, configure your editor to save as UTF-8 without BOM.

**Posts in `_en/_posts/` aren't appearing:** check the date isn't in the future
(Jekyll skips future-dated posts unless you pass `--future`).
