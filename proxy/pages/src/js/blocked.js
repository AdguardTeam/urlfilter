document.addEventListener('DOMContentLoaded', () => {
    const btn = document.getElementById('details-button');
    btn.addEventListener('click', () => {
        btn.classList.toggle('open');
        document.querySelector('.details').classList.toggle('hidden');
    });
});
