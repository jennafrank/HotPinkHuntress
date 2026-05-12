/* ============================================
   HOT PINK HUNTRESS — BLOG LISTING JS
   ============================================ */

(function () {
  if (typeof POSTS === 'undefined') return;

  const grid      = document.getElementById('blogGrid');
  const countNum  = document.getElementById('countNum');
  const noResults = document.getElementById('noResults');
  const searchEl  = document.getElementById('searchInput');
  const filterBtns = document.querySelectorAll('.filter-tag');

  if (!grid) return;

  let activeTag  = 'all';
  let searchTerm = '';

  // ---- Check URL param for pre-filter ----
  const urlParams = new URLSearchParams(window.location.search);
  const tagParam  = urlParams.get('tag');
  if (tagParam) {
    activeTag = tagParam;
    filterBtns.forEach(b => {
      b.classList.toggle('active', b.dataset.tag === tagParam || (tagParam && b.dataset.tag === tagParam));
    });
    // Set correct button active
    filterBtns.forEach(b => {
      b.classList.remove('active');
      if (b.dataset.tag === tagParam) b.classList.add('active');
    });
  }

  // ---- Render posts ----
  function renderPosts() {
    const term = searchTerm.toLowerCase().trim();

    const filtered = POSTS.filter(post => {
      const tagMatch = activeTag === 'all' || post.tags.includes(activeTag);
      const searchMatch = !term ||
        post.title.toLowerCase().includes(term) ||
        post.excerpt.toLowerCase().includes(term) ||
        post.categoryDisplay.toLowerCase().includes(term) ||
        post.tags.some(t => t.includes(term));
      return tagMatch && searchMatch;
    });

    countNum.textContent = filtered.length;

    if (filtered.length === 0) {
      grid.innerHTML = '';
      noResults.classList.add('visible');
      return;
    }

    noResults.classList.remove('visible');

    grid.innerHTML = filtered.map((post, i) => `
      <article class="blog-card${post.featured ? ' blog-featured' : ''} reveal delay-${Math.min(i % 4 + 1, 5)}">
        <div class="blog-card-header">
          <div class="blog-meta">
            <span class="blog-date">${post.dateDisplay}</span>
            <span class="blog-tag">${post.categoryDisplay}</span>
          </div>
          <h2 class="blog-card-title">${post.title}</h2>
        </div>
        <p class="blog-card-excerpt">${post.excerpt}</p>
        <div class="blog-card-footer">
          <a href="blog-post.html?id=${post.id}" class="read-more">Read more</a>
          <span style="font-family:var(--font-mono);font-size:0.72rem;color:var(--text-dim);">${post.readTime} read</span>
        </div>
      </article>
    `).join('');

    // Trigger reveal for newly rendered items
    const revealObserver = new IntersectionObserver((entries) => {
      entries.forEach(e => {
        if (e.isIntersecting) {
          e.target.classList.add('visible');
          revealObserver.unobserve(e.target);
        }
      });
    }, { threshold: 0.1 });

    grid.querySelectorAll('.reveal').forEach(el => {
      // Elements already in view
      const rect = el.getBoundingClientRect();
      if (rect.top < window.innerHeight) {
        el.classList.add('visible');
      } else {
        revealObserver.observe(el);
      }
    });
  }

  // ---- Filter buttons ----
  filterBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      filterBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      activeTag = btn.dataset.tag;
      renderPosts();
    });
  });

  // ---- Search ----
  if (searchEl) {
    let debounceTimer;
    searchEl.addEventListener('input', () => {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => {
        searchTerm = searchEl.value;
        renderPosts();
      }, 220);
    });
  }

  // ---- Initial render ----
  renderPosts();
})();
