let setBgImgBtn;
let isImgDivOpen = false;

function getHtmlElementsById() {
    setBgImgBtn = getId('setBgImgBtn');
}

getHtmlElementsById()

/**
 * Set my background image button click event
 */

function setMyBgImgBtn() {
    setBgImgBtn.addEventListener('click', (e) => {
        if (!isImgDivOpen) {
            optionsContainer.style.display = 'flex';
        } else {
            optionsContainer.style.display = 'none';
        }
        for (let i = 0; i < imgOptions.length; i++) {
            imgOptions[i].addEventListener('click', (e) => {
                let selectedImg = e.target.classList[0];
                document.body.style.backgroundImage = `url('../uploads/bg${selectedImg}.jpg')`;
                document.body.style.backgroundSize = "cover"
                optionsContainer.style.display = 'none';
                isImgDivOpen = false;
            });
        }
        isImgDivOpen = !isImgDivOpen;
    });
}