;; two-mode-mode.el -- switches between tcl and sgml(html) modes
;; $Id$

;; two-mode-mode.el is Copyright David Welton <davidw@dedasys.com>
;; 1999, 2000, 2001

;; two-mode-mode.el may be distributed under the terms of the Apache
;; Software License, Version 1.1

;; As I'm sure is painfully obvious, I don't know much about elisp,
;; but I thought it would be cool to do this mode, for mod_dtcl.  So
;; if you have any comments or suggestions, please email me!

;; These same concepts could be used to do a number of neat 2-mode
;; modes, for things like PHP, or anything else where you have a
;; couple of modes you'd like to use.

;; Use of 'psgml-mode' is highly recommended.  It is, of course, a
;; part of Debian GNU/Linux.

;; Modified by Marco Pantaleoni <panta@elasticworld.org>
;; to allow execution of an hook on mode switching.
;; Also added a standard mode hook and some documentation strings.

;; configure these:
(defvar two-mode-lmatch "<?"
  "Open tag for `second' mode.")
(defvar two-mode-rmatch "?>"
  "Close tag for `second' mode.")

(defvar default-mode (list 'html-mode "HTML")
  "Default mode.")
(defvar second-mode  (list 'tcl-mode "Tcl")
  "Second mode: mode used inside special tags.")
;; ----------------

(defvar two-mode-update 0)
(defvar two-mode-mode-idle-timer nil)
(defvar two-mode-bool nil)
(defvar two-mode-mode-delay (/ (float 1) (float 8)))

;; Two mode hook
(defvar two-mode-hook nil
  "*Hook called by `two-mode'.")
(setq two-mode-hook nil)

;; Mode switching hook
(defvar two-mode-switch-hook nil
  "*Hook called upon mode switching.")
(setq two-mode-switch-hook nil)

(defun two-mode-mode-setup ()
  (make-local-hook 'post-command-hook)
  (add-hook 'post-command-hook 'two-mode-mode-need-update nil t)
  (make-local-variable 'minor-mode-alist)
  (make-local-variable 'two-mode-bool)
  (setq two-mode-bool t)
  (when two-mode-mode-idle-timer
    (cancel-timer two-mode-mode-idle-timer))
  (setq two-mode-mode-idle-timer (run-with-idle-timer two-mode-mode-delay t 'two-mode-mode-update-mode))
  (or (assq 'two-mode-bool minor-mode-alist)
      (setq minor-mode-alist
	    (cons '(two-mode-bool " two-mode") minor-mode-alist))))

(defun two-mode-mode-need-update ()
  (setq two-mode-update 1))

(defun two-mode-change-mode (to-mode)
  (if (string= to-mode mode-name)
      t
    (progn 
      (save-excursion
	(if (string= to-mode (cadr second-mode))
	    (funcall (car second-mode))
	(funcall (car default-mode))))
      (two-mode-mode-setup)
      (if two-mode-switch-hook
	  (run-hooks 'two-mode-switch-hook))
      (if (eq font-lock-mode t)
	  (font-lock-fontify-buffer))
      (turn-on-font-lock-if-enabled))))

(defun two-mode-mode-update-mode ()
  (when (and two-mode-bool two-mode-update)
    (setq two-mode-update 0)
    (let ((lm -1)
	  (rm -1))
      (save-excursion 
	(if (search-backward two-mode-lmatch nil t)
	    (setq lm (point))
	  (setq lm -1)))
      (save-excursion
	(if (search-backward two-mode-rmatch nil t)
	    (setq rm (point))
	  (setq rm -1)))
      (if (and (= lm -1) (= rm -1))
	  (two-mode-change-mode (cadr default-mode))
	(if (>= lm rm)
	    (two-mode-change-mode (cadr second-mode))
	  (two-mode-change-mode (cadr default-mode)))))))

(defun two-mode-mode ()
  "Turn on two-mode-mode"
  (interactive)
  (funcall (car default-mode))
  (two-mode-mode-setup)
  (if two-mode-hook
     (run-hooks 'two-mode-hook)))

(provide 'two-mode-mode)

