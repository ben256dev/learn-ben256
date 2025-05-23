// animation.js
export function load_animate_css()
{
    if (!document.getElementById('animatecss'))
    {
        const link = document.createElement('link');
        link.id = 'animatecss';
        link.rel = 'stylesheet';
        link.href = 'https://cdnjs.cloudflare.com/ajax/libs/animate.css/4.1.1/animate.min.css';
        document.head.appendChild(link);
    }
}

export function reset_animation(el)
{
    load_animate_css();

    const animate_classes = Array.from(el.classList)
        .filter(c => c.startsWith('animate__'));
    el.classList.remove(...animate_classes);
    void el.offsetWidth;
    el.classList.add(...animate_classes);
}
