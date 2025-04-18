let currentNoteId = null;

function viewNote(id, title, content) {
    currentNoteId = id;
    document.getElementById('noteModalLabel').innerText = title;
    document.getElementById('noteContent').innerText = content;
    const modal = new bootstrap.Modal(document.getElementById('noteModal'));
    modal.show();
}
function showNotePopup(note) {
    document.getElementById('noteText').innerText = note;
    document.getElementById('notePopup').style.display = 'block';
}

function closeNotePopup() {
    document.getElementById('notePopup').style.display = 'none';
}

function editNote() {
    if (!currentNoteId) return;
    window.location.href = `/edit_note/${currentNoteId}`;
}

function deleteNote() {
    if (!currentNoteId) return;
    if (confirm('Are you sure you want to delete this note?')) {
        fetch(`/delete_note/${currentNoteId}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
        }).then((response) => {
            if (response.ok) {
                window.location.reload();
            } else {
                alert('Failed to delete the note.');
            }
        });
    }
}
