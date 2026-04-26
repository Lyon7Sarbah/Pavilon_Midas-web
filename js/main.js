// ============================================
// Pavilion Midas Academy Ltd — MAIN JAVASCRIPT
// ============================================

document.addEventListener('DOMContentLoaded', function () {

  // ===== NAVBAR SCROLL =====
  const navbar = document.querySelector('.navbar');
  function handleScroll() {
    if (window.scrollY > 50) {
      navbar.classList.add('scrolled');
    } else {
      navbar.classList.remove('scrolled');
    }
    // scroll-to-top
    const scrollTop = document.querySelector('.scroll-top');
    if (scrollTop) {
      scrollTop.classList.toggle('show', window.scrollY > 400);
    }
  }
  window.addEventListener('scroll', handleScroll);

  // ===== HAMBURGER MENU =====
  const hamburger = document.querySelector('.hamburger');
  const mobileMenu = document.querySelector('.mobile-menu');
  if (hamburger && mobileMenu) {
    hamburger.addEventListener('click', function () {
      const isOpen = mobileMenu.classList.toggle('open');
      this.querySelectorAll('span').forEach((s, i) => {
        if (isOpen) {
          if (i === 0) s.style.cssText = 'transform:rotate(45deg) translate(5px,5px)';
          if (i === 1) s.style.cssText = 'opacity:0;transform:scaleX(0)';
          if (i === 2) s.style.cssText = 'transform:rotate(-45deg) translate(5px,-5px)';
        } else {
          s.style.cssText = '';
        }
      });
    });
    // Close on link click
    mobileMenu.querySelectorAll('a').forEach(a => {
      a.addEventListener('click', () => {
        mobileMenu.classList.remove('open');
        hamburger.querySelectorAll('span').forEach(s => s.style.cssText = '');
      });
    });
  }

  // ===== SCROLL TO TOP =====
  const scrollTopBtn = document.querySelector('.scroll-top');
  if (scrollTopBtn) {
    scrollTopBtn.addEventListener('click', () => {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    });
  }

  // ===== FADE UP ANIMATION =====
  const fadeEls = document.querySelectorAll('.fade-up, .fade-in');
  if (fadeEls.length) {
    const obs = new IntersectionObserver((entries) => {
      entries.forEach(e => {
        if (e.isIntersecting) {
          const delay = e.target.dataset.delay || 0;
          setTimeout(() => e.target.classList.add('visible'), parseInt(delay));
        }
      });
    }, { threshold: 0.12, rootMargin: '0px 0px -40px 0px' });
    fadeEls.forEach(el => obs.observe(el));
  }

  // ===== COUNTER ANIMATION =====
  function animateCounter(el) {
    const target = parseFloat(el.dataset.count);
    const suffix = el.dataset.suffix || '';
    const prefix = el.dataset.prefix || '';
    const isDecimal = el.dataset.decimal === 'true';
    const duration = 2200;
    const steps = 80;
    const increment = target / steps;
    let current = 0;
    const timer = setInterval(() => {
      current = Math.min(current + increment, target);
      el.textContent = prefix + (isDecimal ? current.toFixed(1) : Math.floor(current)) + suffix;
      if (current >= target) clearInterval(timer);
    }, duration / steps);
  }
  const counterEls = document.querySelectorAll('[data-count]');
  if (counterEls.length) {
    const counterObs = new IntersectionObserver((entries) => {
      entries.forEach(e => {
        if (e.isIntersecting) {
          animateCounter(e.target);
          counterObs.unobserve(e.target);
        }
      });
    }, { threshold: 0.5 });
    counterEls.forEach(el => counterObs.observe(el));
  }

  // ===== ACCORDION =====
  document.querySelectorAll('.accordion-header').forEach(header => {
    header.addEventListener('click', function () {
      const item = this.closest('.accordion-item');
      const isOpen = item.classList.contains('open');
      // Close all
      document.querySelectorAll('.accordion-item.open').forEach(i => i.classList.remove('open'));
      if (!isOpen) item.classList.add('open');
    });
  });

  // ===== TABS =====
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', function () {
      const tabGroup = this.closest('[data-tabs]');
      const target = this.dataset.tab;
      // Update buttons
      tabGroup.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      this.classList.add('active');
      // Update panels
      const panels = document.querySelectorAll('[data-tab-panel]');
      panels.forEach(p => {
        p.style.display = p.dataset.tabPanel === target ? 'block' : 'none';
      });
    });
  });

  // ===== PRICING TOGGLE =====
  const pricingToggle = document.querySelector('#pricingToggle');
  if (pricingToggle) {
    pricingToggle.addEventListener('change', function () {
      document.querySelectorAll('[data-monthly]').forEach(el => {
        el.textContent = this.checked ? el.dataset.yearly : el.dataset.monthly;
      });
      document.querySelectorAll('[data-period]').forEach(el => {
        el.textContent = this.checked ? '/year' : '/month';
      });
    });
  }

  // ===== ACTIVE NAV LINK =====
  const currentPage = window.location.pathname.split('/').pop() || 'index.html';
  document.querySelectorAll('.nav-links a, .mobile-menu a').forEach(link => {
    const href = link.getAttribute('href');
    if (href === currentPage || (currentPage === '' && href === 'index.html')) {
      link.classList.add('active');
    }
  });

  // ===== FORM SUBMISSION =====
  document.querySelectorAll('form[data-ajax]').forEach(form => {
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      const btn = this.querySelector('[type="submit"]');
      const orig = btn.textContent;
      btn.textContent = 'Processing...';
      btn.disabled = true;
      setTimeout(() => {
        btn.textContent = orig;
        btn.disabled = false;
        // Show success message
        const msg = document.createElement('div');
        msg.className = 'notice';
        msg.innerHTML = '<span class="notice-icon">✓</span> Your message has been sent successfully!';
        this.appendChild(msg);
        this.reset();
        setTimeout(() => msg.remove(), 5000);
      }, 1500);
    });
  });

  // ===== FLOATING NAVBAR ACTIVE =====
  handleScroll();
});
