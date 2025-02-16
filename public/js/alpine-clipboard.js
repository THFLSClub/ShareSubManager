async function copy(string) {
    try {
        // 使用 navigator.clipboard.writeText 方法将字符串写入剪贴板
        await navigator.clipboard.writeText(string);
        console.log('文本已成功复制到剪贴板');
    } catch (error) {
        // 如果复制过程中出现错误，使用旧的 document.execCommand 方法作为备用方案
        const textarea = document.createElement('textarea');
        textarea.value = string;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.select();
        try {
            const successful = document.execCommand('copy');
            if (successful) {
                console.log('文本已成功复制到剪贴板');
            } else {
                console.error('复制到剪贴板失败');
            }
        } catch (err) {
            console.error('复制到剪贴板时发生错误:', err);
        }
        document.body.removeChild(textarea);
    }
}
