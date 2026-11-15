# PromptShield AI — Firebase Hosting Deployment Guide

This guide details how the frontend dashboard is deployed to Firebase Hosting on the existing site [https://pomptshieldai.web.app/](https://pomptshieldai.web.app/) under project **Surya**.

---

## 1. Firebase Configuration

The repository is pre-configured with:
- [`.firebaserc`](../.firebaserc): Links the default project to `surya` and target `pomptshieldai`.
- [`firebase.json`](../firebase.json): Configures hosting for site `pomptshieldai`, SPA rewrites to `/index.html`, and security headers.

---

## 2. Deploying from Your Terminal

Since Firebase CLI requires an active interactive login on your machine:

1. **Log in to Firebase**:
   ```bash
   npx firebase-tools login
   ```
   *(This opens a browser window for Google authentication. Ensure you sign in with the Google account owning the "Surya" project.)*

2. **Verify Project ID**:
   ```bash
   npx firebase-tools projects:list
   ```
   Confirm your project ID for "Surya" (e.g. `surya` or `surya-xxxxx`). If your project ID has a suffix, update `.firebaserc` accordingly.

3. **Build the Frontend**:
   ```bash
   npm run frontend:build
   ```
   *(Or `cd frontend && npm install && npm run build`)*

4. **Deploy to Firebase Hosting**:
   ```bash
   npx firebase-tools deploy --only hosting
   ```
   Or explicitly targeting the site:
   ```bash
   npx firebase-tools deploy --only hosting:pomptshieldai --project <your-surya-project-id>
   ```

5. **Access Your Live Dashboard**:
   Open [https://pomptshieldai.web.app/](https://pomptshieldai.web.app/) in your browser.
