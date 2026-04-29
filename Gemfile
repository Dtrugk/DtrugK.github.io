source "https://rubygems.org"

gem "jekyll-theme-chirpy", "~> 7.2"

# Plugins Chirpy uses
group :jekyll_plugins do
  gem "jekyll-paginate"
  gem "jekyll-redirect-from"
  gem "jekyll-seo-tag"
  gem "jekyll-sitemap"
  gem "jekyll-archives"
  gem "jekyll-include-cache"
end

group :test do
  gem "html-proofer", "~> 5.0"
end

# Windows / JRuby compatibility
platforms :mingw, :x64_mingw, :mswin, :jruby do
  gem "tzinfo", ">= 1", "< 3"
  gem "tzinfo-data"
end

gem "wdm", "~> 0.2.0", :platforms => [:mingw, :x64_mingw, :mswin]
gem "http_parser.rb", "~> 0.6.0", :platforms => [:jruby]