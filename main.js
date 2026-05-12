/* ============================================
   HOT PINK HUNTRESS — MAIN JS
   ============================================ */

// ---- Nav toggle (mobile) ----
const navToggle = document.getElementById('navToggle');
const navLinks  = document.getElementById('navLinks');

if (navToggle && navLinks) {
  navToggle.addEventListener('click', () => {
    navLinks.classList.toggle('open');
    const isOpen = navLinks.classList.contains('open');
    navToggle.setAttribute('aria-expanded', isOpen);
  });

  // Close when a link is clicked
  navLinks.querySelectorAll('a').forEach(link => {
    link.addEventListener('click', () => navLinks.classList.remove('open'));
  });
}

// ---- Active nav link on scroll ----
const sections = document.querySelectorAll('section[id], footer[id]');
const allNavLinks = document.querySelectorAll('.nav-links a');

function setActiveNav() {
  let current = '';
  sections.forEach(sec => {
    const top = sec.offsetTop - 80;
    if (window.scrollY >= top) current = sec.id;
  });
  allNavLinks.forEach(a => {
    a.classList.remove('active');
    if (a.getAttribute('href') === `#${current}`) a.classList.add('active');
  });
}

window.addEventListener('scroll', setActiveNav, { passive: true });

// ---- Scroll reveal ----
const revealEls = document.querySelectorAll('.reveal');

const revealObserver = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      entry.target.classList.add('visible');
      revealObserver.unobserve(entry.target);
    }
  });
}, { threshold: 0.12, rootMargin: '0px 0px -40px 0px' });

revealEls.forEach(el => revealObserver.observe(el));

// ---- Homepage blog preview ----
function renderHomePosts() {
  const container = document.getElementById('homeBlogPosts');
  if (!container || typeof POSTS === 'undefined') return;

  const recent = POSTS.slice(0, 3);
  container.innerHTML = recent.map((p, i) => `
    <article class="blog-card reveal delay-${i + 1}" data-id="${p.id}">
      <div class="blog-card-header">
        <div class="blog-meta">
          <span class="blog-date">${p.dateDisplay}</span>
          <span class="blog-tag">${p.categoryDisplay}</span>
        </div>
        <h3 class="blog-card-title">${p.title}</h3>
      </div>
      <p class="blog-card-excerpt">${p.excerpt}</p>
      <div class="blog-card-footer">
        <a href="blog-post.html?id=${p.id}" class="read-more">Read more</a>
        <span style="font-family:var(--font-mono);font-size:0.72rem;color:var(--text-dim);">${p.readTime} read</span>
      </div>
    </article>
  `).join('');

  // Re-observe new reveal elements
  container.querySelectorAll('.reveal').forEach(el => revealObserver.observe(el));
}

renderHomePosts();

// ---- Typing effect on hero terminal (optional enhancement) ----
function typeEffect(el, text, speed = 40) {
  if (!el) return;
  el.textContent = '';
  let i = 0;
  const interval = setInterval(() => {
    el.textContent += text[i];
    i++;
    if (i >= text.length) clearInterval(interval);
  }, speed);
}

// ---- Glitch effect on logo ----
const logo = document.querySelector('.nav-logo');
if (logo) {
  setInterval(() => {
    if (Math.random() > 0.92) {
      logo.style.textShadow = '2px 0 #00f5c4, -2px 0 #FF1493';
      setTimeout(() => {
        logo.style.textShadow = '';
      }, 80);
    }
  }, 2000);
}

// ---- Parallax on hero illustration ----
const heroIllustration = document.querySelector('.hero-illustration');
if (heroIllustration) {
  window.addEventListener('scroll', () => {
    const scroll = window.scrollY;
    if (scroll < window.innerHeight) {
      heroIllustration.style.transform = `translateY(${scroll * 0.08}px)`;
    }
  }, { passive: true });
}

// ---- Card hover tilt ----
document.querySelectorAll('.card').forEach(card => {
  card.addEventListener('mousemove', e => {
    const rect = card.getBoundingClientRect();
    const x = ((e.clientX - rect.left) / rect.width  - 0.5) * 8;
    const y = ((e.clientY - rect.top)  / rect.height - 0.5) * 8;
    card.style.transform = `translateY(-4px) rotateX(${-y}deg) rotateY(${x}deg)`;
  });
  card.addEventListener('mouseleave', () => {
    card.style.transform = '';
  });
});

// ---- Cursor glow trail (subtle) ----
let mouseX = 0, mouseY = 0;
const trail = document.createElement('div');
trail.style.cssText = `
  position:fixed; width:200px; height:200px;
  background:radial-gradient(circle, rgba(255,45,120,0.04) 0%, transparent 70%);
  border-radius:50%; pointer-events:none; z-index:9998;
  transform:translate(-50%,-50%); transition:left 0.15s, top 0.15s;
`;
document.body.appendChild(trail);

document.addEventListener('mousemove', e => {
  mouseX = e.clientX;
  mouseY = e.clientY;
  trail.style.left = mouseX + 'px';
  trail.style.top  = mouseY + 'px';
}, { passive: true });
